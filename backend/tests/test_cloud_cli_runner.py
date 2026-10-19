"""The sandbox and the budgets, with no Docker daemon anywhere.

`build_container_command` and `build_exec_command` are pure, so the container's
security posture is asserted against argv rather than against a running daemon —
the same shape `test_prowler_runner` already uses, and the reason a regression
in the sandbox flags fails in CI rather than on a customer's project.
"""

from __future__ import annotations

import subprocess

import pytest

from app.integrations import cloud_cli_guards as g
from app.integrations import cloud_cli_runner as r

IMAGE = "google/cloud-sdk:583.0.0-slim"
DOCKER_HOST = "unix:///var/run/docker.sock"


TOKEN = "ya29.a0-fake-access-token"


def container_cmd(token: str = TOKEN) -> list[str]:
    return r.build_container_command(
        container_name="cloud-cli-abc", image=IMAGE, access_token=token
    )


# ── the sandbox ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "flag",
    [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=512m",
        "--cpus=1",
        "--pids-limit=64",
    ],
)
def test_every_sandbox_flag_is_present(flag):
    assert flag in container_cmd()


def test_the_container_runs_as_a_non_root_user():
    cmd = container_cmd()
    assert cmd[cmd.index("--user") + 1] == "1000:1000"


def test_the_two_writable_paths_are_tmpfs_and_nothing_else_is():
    cmd = container_cmd()
    tmpfs = [cmd[i + 1] for i, t in enumerate(cmd) if t == "--tmpfs"]
    assert sorted(tmpfs) == ["/config", "/tmp"]


def test_the_docker_socket_is_never_mounted():
    """Mounting it is effectively host root, and this container runs argv a
    model composed."""
    assert "docker.sock" not in " ".join(container_cmd())


def test_nothing_is_bind_mounted_into_the_container_at_all():
    """The scanner mounts an ADC file; this deliberately mounts nothing.

    `GOOGLE_APPLICATION_CREDENTIALS` is a *client library* convention and
    `gcloud` is not a client library — with only that set it refuses every
    command with "You do not currently have an active account selected", which
    reads as a permissions problem and is not one. Verified against a real
    project before the token route was written."""
    assert "-v" not in container_cmd()


def test_the_container_gets_a_short_lived_token_and_nothing_refreshable():
    """Strictly less privilege than a mounted credential: the token is the
    scanner service account's, expires in an hour, cannot be refreshed, and
    cannot be exchanged for another identity."""
    cmd = container_cmd()
    assert f"CLOUDSDK_AUTH_ACCESS_TOKEN={TOKEN}" in cmd
    joined = " ".join(cmd)
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in joined
    assert "adc.json" not in joined


def test_the_impersonation_flag_is_not_injected_alongside_the_token():
    """The token already *is* the target service account, so asking it to
    impersonate itself needs tokenCreator on itself and fails. The identity
    boundary moves to the token; G3 still refuses a caller-supplied flag."""
    checked = g.check_command(
        "gcloud",
        ["projects", "describe", "p"],
        project_id="p",
        target_sa_email="sa@p.iam.gserviceaccount.com",
    )
    assert not any(t.startswith("--impersonate-service-account") for t in checked.argv)
    assert "--project=p" in checked.argv


def test_the_container_exits_on_its_own_if_nothing_reaps_it():
    """A worker killed mid-run leaves no reaper, so the container's own lifetime
    is the backstop — `tail -f /dev/null` would leave it running forever."""
    cmd = container_cmd()
    assert cmd[-2] == "sleep"
    assert int(cmd[-1]) > g.MAX_CLI_WALL_CLOCK_SECONDS


def test_a_pinned_image_tag_is_used_not_a_floating_one():
    cmd = container_cmd()
    assert IMAGE in cmd
    assert ":latest" not in " ".join(cmd)


# ── the argv boundary ────────────────────────────────────────────────────────


def test_the_exec_argv_keeps_every_token_separate():
    argv = ["gcloud", "compute", "instances", "list", "--filter=status=RUNNING", "--limit=5"]
    cmd = r.build_exec_command(container_name="cloud-cli-abc", argv=argv)
    assert cmd[:3] == ["docker", "exec", "cloud-cli-abc"]
    assert cmd[3:] == argv


def test_no_built_command_ever_contains_a_shell_metacharacter():
    for token in container_cmd() + r.build_exec_command(
        container_name="cloud-cli-abc", argv=["gcloud", "projects", "describe", "p"]
    ):
        for meta in g.SHELL_METACHARACTERS:
            assert meta not in token


# ── budgets ──────────────────────────────────────────────────────────────────


class _Completed:
    def __init__(self, returncode=0, stdout="{}", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def session(monkeypatch, *, run=None):
    s = r.CloudCliSession(image=IMAGE, docker_host=DOCKER_HOST, run_id="test")
    s.container_id = "deadbeef"
    s.started_at = r.time.monotonic()
    monkeypatch.setattr(r.subprocess, "run", run or (lambda *a, **k: _Completed()))
    return s


def test_the_command_budget_is_an_explanation_not_a_crash(monkeypatch):
    s = session(monkeypatch)
    for _ in range(g.MAX_CLI_COMMANDS_PER_RUN):
        s.run(["gcloud", "projects", "describe", "p"])
    with pytest.raises(r.BudgetExhausted) as exc:
        s.run(["gcloud", "projects", "describe", "p"])
    assert "reason with what you already have" in str(exc.value)
    assert s.remaining_commands() == 0


def test_the_wall_clock_budget_is_enforced_across_the_run(monkeypatch):
    s = session(monkeypatch)
    s.started_at = r.time.monotonic() - g.MAX_CLI_WALL_CLOCK_SECONDS - 1
    with pytest.raises(r.BudgetExhausted) as exc:
        s.run(["gcloud", "projects", "describe", "p"])
    assert "time budget" in str(exc.value)


def test_a_per_command_timeout_is_a_result_not_an_exception(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=g.CLI_COMMAND_TIMEOUT_SECONDS)

    s = session(monkeypatch, run=boom)
    result = s.run(["gcloud", "projects", "describe", "p"])
    assert result.ok is False
    assert result.exit_code is None
    assert "timeout" in result.stderr
    # It still costs a command: a timed-out call did the expensive part.
    assert s.commands_run == 1


def test_capped_output_says_so_rather_than_looking_complete(monkeypatch):
    big = "x" * (g.MAX_CLI_OUTPUT_BYTES + 5_000)
    s = session(monkeypatch, run=lambda *a, **k: _Completed(stdout=big))
    result = s.run(["gcloud", "compute", "instances", "list", "--limit=500"])
    assert result.truncated is True
    assert len(result.stdout.encode()) <= g.MAX_CLI_OUTPUT_BYTES


def test_output_under_the_cap_is_not_flagged_as_truncated(monkeypatch):
    s = session(monkeypatch, run=lambda *a, **k: _Completed(stdout='{"ok": true}'))
    assert s.run(["gcloud", "projects", "describe", "p"]).truncated is False


# ── failures come back verbatim ──────────────────────────────────────────────


def test_a_permission_error_comes_back_verbatim_not_flattened(monkeypatch):
    """The single most informative thing this feature can learn: the difference
    between "the agent saw no org policies" and "the agent was not allowed to
    look". Flattening it into "failed" is what makes a report's silence
    unreadable."""
    denied = (
        "ERROR: (gcloud.resource-manager.org-policies.list) User "
        "[prowler@p.iam.gserviceaccount.com] does not have permission to access "
        "organizations instance [123] (or it may not exist): Request had "
        "insufficient authentication scopes."
    )
    s = session(monkeypatch, run=lambda *a, **k: _Completed(returncode=1, stdout="", stderr=denied))
    result = s.run(["gcloud", "resource-manager", "org-policies", "list"])
    assert result.ok is False
    assert result.exit_code == 1
    assert result.stderr == denied


# ── lifecycle ────────────────────────────────────────────────────────────────


def test_the_container_is_torn_down_even_when_the_run_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(
        r.subprocess, "run", lambda cmd, **k: (calls.append(cmd), _Completed(stdout="cid"))[1]
    )
    with pytest.raises(RuntimeError):
        with r.CloudCliSession(image=IMAGE, docker_host=DOCKER_HOST, run_id="test"):
            raise RuntimeError("the investigation blew up")
    assert calls[-1][:3] == ["docker", "rm", "-f"]


def test_a_failed_launch_is_named_rather_than_returning_a_dead_session(monkeypatch):
    monkeypatch.setattr(
        r.subprocess,
        "run",
        lambda *a, **k: _Completed(returncode=125, stdout="", stderr="no such image"),
    )
    with pytest.raises(r.CloudCliLaunchError) as exc:
        r.CloudCliSession(image=IMAGE, docker_host=DOCKER_HOST).__enter__()
    assert "no such image" in str(exc.value)


def test_orphans_are_reaped_by_name_prefix(monkeypatch):
    calls = []

    def fake(cmd, **k):
        calls.append(cmd)
        return _Completed(stdout="abc\ndef\n" if cmd[:2] == ["docker", "ps"] else "")

    monkeypatch.setattr(r.subprocess, "run", fake)
    assert r.reap_orphaned_containers(docker_host=DOCKER_HOST) == ["abc", "def"]
    assert calls[0][-1] == f"name={r.CONTAINER_NAME_PREFIX}"
    assert calls[-1] == ["docker", "rm", "-f", "abc", "def"]


def test_nothing_is_removed_when_there_are_no_orphans(monkeypatch):
    calls = []
    monkeypatch.setattr(
        r.subprocess, "run", lambda cmd, **k: (calls.append(cmd), _Completed(stdout="\n"))[1]
    )
    assert r.reap_orphaned_containers(docker_host=DOCKER_HOST) == []
    assert len(calls) == 1


# ── per-pillar budget ────────────────────────────────────────────────────────


def test_one_pillar_cannot_eat_the_whole_run_budget(monkeypatch):
    """The run bound alone does not stop the first pillar spending everything
    and leaving the other four to reason with nothing."""
    s = session(monkeypatch)
    for _ in range(g.MAX_CLI_COMMANDS_PER_PILLAR):
        s.run(["gcloud", "projects", "describe", "p"], pillar="Security")
    with pytest.raises(r.BudgetExhausted) as exc:
        s.run(["gcloud", "projects", "describe", "p"], pillar="Security")
    assert "Security" in str(exc.value)
    # A different pillar still has its own allowance, and the run does too.
    assert s.remaining_commands("Reliability") > 0
    assert s.run(["gcloud", "projects", "describe", "p"], pillar="Reliability").ok


def test_an_unnamed_command_counts_only_against_the_run(monkeypatch):
    s = session(monkeypatch)
    s.run(["gcloud", "projects", "describe", "p"])
    assert s.commands_run == 1
    assert s.commands_by_pillar == {}


# ── orphan reaping is wired, not just written ────────────────────────────────


def test_the_worker_reaps_orphans_on_startup(monkeypatch):
    """The function existing is not the criterion — a container orphaned by a
    killed worker has to actually be cleaned up."""
    from app.worker import celery_app as ca

    called = {}
    monkeypatch.setattr(
        ca, "get_settings", lambda: {"CLOUD_CLI_ENABLED": "true", "DOCKER_HOST": DOCKER_HOST}
    )
    monkeypatch.setattr(
        r, "reap_orphaned_containers", lambda **kw: called.setdefault("kw", kw) or ["abc"]
    )
    ca._reap_cloud_cli_orphans()
    assert called["kw"]["docker_host"] == DOCKER_HOST


def test_the_worker_still_starts_when_docker_is_unreachable(monkeypatch):
    """A worker that cannot reach Docker must still start and serve reports."""
    from app.worker import celery_app as ca

    monkeypatch.setattr(
        ca, "get_settings", lambda: {"CLOUD_CLI_ENABLED": "true", "DOCKER_HOST": DOCKER_HOST}
    )
    monkeypatch.setattr(
        r,
        "reap_orphaned_containers",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("daemon unreachable")),
    )
    ca._reap_cloud_cli_orphans()


def test_nothing_is_reaped_when_the_feature_is_switched_off(monkeypatch):
    from app.worker import celery_app as ca

    monkeypatch.setattr(
        ca, "get_settings", lambda: {"CLOUD_CLI_ENABLED": "false", "DOCKER_HOST": DOCKER_HOST}
    )
    monkeypatch.setattr(
        r, "reap_orphaned_containers", lambda **kw: pytest.fail("should not have been called")
    )
    ca._reap_cloud_cli_orphans()


class _Settings(dict):
    """A settings stub with the `redis_url` property the slot reaper needs.

    The container half only ever subscripts, which is why the tests above can
    pass a bare dict; the slot half reads the attribute.
    """

    redis_url = "redis://localhost:6379/0"


class _FakeRedis:
    def __init__(self, keys):
        self.keys = dict.fromkeys(keys)
        self.deleted: list[str] = []

    def scan_iter(self, match=None):
        return iter(list(self.keys))

    def delete(self, *keys):
        self.deleted.extend(keys)
        for key in keys:
            self.keys.pop(key, None)


def test_a_slot_left_by_a_killed_worker_is_released_not_left_to_expire(monkeypatch):
    """Reaping the container alone fixes the visible half. The slot is the half
    that blocks the next report — for thirty minutes, and locally there is one."""
    from app.agents import cloud_context as cc
    from app.worker import celery_app as ca

    fake = _FakeRedis(["cli:slot:0", "cli:slot:1"])
    monkeypatch.setattr(
        ca, "get_settings",
        lambda: _Settings(CLOUD_CLI_ENABLED="true", DOCKER_HOST=DOCKER_HOST),
    )
    monkeypatch.setattr(r, "reap_orphaned_containers", lambda **kw: [])
    monkeypatch.setattr(cc.redis, "from_url", lambda *a, **k: fake)

    ca._reap_cloud_cli_orphans()
    assert sorted(fake.deleted) == ["cli:slot:0", "cli:slot:1"]


def test_no_slot_is_touched_when_none_are_held(monkeypatch):
    from app.agents import cloud_context as cc

    fake = _FakeRedis([])
    assert cc.reap_orphaned_slots(fake) == []
    assert fake.deleted == []


def test_an_unreachable_docker_daemon_does_not_cost_the_slot_reclamation(monkeypatch):
    """The two halves need different infrastructure — Docker and Redis — so one
    being down must not skip the other."""
    from app.agents import cloud_context as cc
    from app.worker import celery_app as ca

    fake = _FakeRedis(["cli:slot:0"])
    monkeypatch.setattr(
        ca, "get_settings",
        lambda: _Settings(CLOUD_CLI_ENABLED="true", DOCKER_HOST=DOCKER_HOST),
    )
    monkeypatch.setattr(
        r,
        "reap_orphaned_containers",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("daemon unreachable")),
    )
    monkeypatch.setattr(cc.redis, "from_url", lambda *a, **k: fake)

    ca._reap_cloud_cli_orphans()
    assert fake.deleted == ["cli:slot:0"]


def test_the_scan_worker_never_reaps(monkeypatch):
    """Since the worker split only the reports process opens recon containers.
    Reaping from the scan worker would destroy a live report's container every
    time the scan worker restarted for its own reasons."""
    from app.worker import celery_app as ca
    from app.worker import run_worker as rw

    monkeypatch.setenv(rw.ROLE_ENV_VAR, rw.SCANS)
    monkeypatch.setattr(
        ca, "get_settings", lambda: pytest.fail("settings should not have been read")
    )
    ca._reap_cloud_cli_orphans()


def test_a_worker_with_no_declared_role_still_reaps(monkeypatch):
    """The guard names the scan role rather than the reports one, so a worker
    started by hand — one process, both queues, the pre-split shape — is not
    silently left without a reaper."""
    from app.worker import celery_app as ca
    from app.worker import run_worker as rw

    monkeypatch.delenv(rw.ROLE_ENV_VAR, raising=False)
    called = {}
    monkeypatch.setattr(
        ca, "get_settings", lambda: {"CLOUD_CLI_ENABLED": "true", "DOCKER_HOST": DOCKER_HOST}
    )
    monkeypatch.setattr(r, "reap_orphaned_containers", lambda **kw: called.setdefault("k", 1) or [])
    ca._reap_cloud_cli_orphans()
    assert called
