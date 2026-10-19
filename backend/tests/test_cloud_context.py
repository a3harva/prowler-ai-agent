"""The per-run layer: cache, semaphore, evidence log and the failure policy.

No Docker daemon and no Redis server — the session and the Redis client are
both stubbed, because what is being asserted here is the *policy*: what gets
charged to a budget, what gets cached, what a rejection looks like to a model,
and what happens when live context cannot be had at all.
"""

from __future__ import annotations

import pytest

from app.agents import cloud_context as cc
from app.integrations import cloud_cli_guards as g
from app.integrations.cloud_cli_runner import BudgetExhausted, CommandResult

PROJECT = "synthetic-project-id"
SA = "scanner@synthetic-project.invalid"


class _FakeRedis:
    """Enough of redis-py for a slot and a cache, with a switch for outages."""

    def __init__(self, *, broken: bool = False):
        self.data: dict[str, str] = {}
        self.broken = broken

    def _check(self):
        if self.broken:
            raise RuntimeError("connection refused")

    def get(self, key):
        self._check()
        return self.data.get(key)

    def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    def delete(self, key):
        self._check()
        self.data.pop(key, None)


class _FakeSession:
    def __init__(self, results=None):
        self.calls: list[list[str]] = []
        self.commands_run = 0
        self.results = list(results or [])

    def remaining_commands(self, pillar=None):
        return 99

    def run(self, argv, *, display=None, pillar=None):
        self.calls.append(argv)
        self.commands_run += 1
        if self.results:
            nxt = self.results.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt
        return CommandResult(
            ok=True, exit_code=0, stdout='{"ok": true}', stderr="",
            truncated=False, duration_ms=12, command=display or " ".join(argv),
        )


def context(*, results=None, redis=None):
    return cc.CloudContext(
        session=_FakeSession(results),
        redis_client=redis or _FakeRedis(),
        thread_id="RPT-test",
        project_id=PROJECT,
        target_sa_email=SA,
    )


# ── what the model sees ──────────────────────────────────────────────────────


def test_a_rejected_command_comes_back_explaining_the_fix_and_is_not_run():
    ctx = context()
    result = ctx.run(binary="gcloud", args=["compute", "instances", "delete", "x"], why="tidy up")
    assert result["ok"] is False
    assert result["rejected_by"] == "G2_verb"
    assert "write verb" in result["reason"]
    assert result["fix"]
    assert ctx.session.calls == []


def test_a_caller_supplied_project_is_refused_rather_than_overridden():
    """Silently overriding it would make the evidence appendix a lie about what
    the agent asked for."""
    ctx = context()
    result = ctx.run(
        binary="gcloud",
        args=["compute", "instances", "list", "--limit=5", "--project=someone-else"],
        why="check the other project",
    )
    assert result["rejected_by"] == "G3_flags"
    assert ctx.session.calls == []


def test_a_permission_error_comes_back_verbatim():
    denied = "ERROR: (gcloud.asset.search-all-iam-policies) does not have permission"
    ctx = context(results=[CommandResult(
        ok=False, exit_code=1, stdout="", stderr=denied,
        truncated=False, duration_ms=9, command="x",
    )])
    result = ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="check")
    assert result["ok"] is False
    assert result["stderr"] == denied


def test_running_out_of_budget_is_an_explanation_not_a_crash():
    ctx = context(results=[BudgetExhausted("command budget exhausted for this run")])
    result = ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="check")
    assert result["budget_exhausted"] is True
    assert "budget exhausted" in result["reason"]


# ── the run-scoped cache ─────────────────────────────────────────────────────


def test_repeating_a_command_costs_nothing_and_returns_identical_bytes():
    """The determinism property. `repair` re-reading a command must not get
    different bytes from the ones the paragraph it is repairing was written
    from — a report contradicting itself with no diff to explain it."""
    ctx = context()
    first = ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="check")
    second = ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="check again")
    assert len(ctx.session.calls) == 1
    assert second["cached"] is True
    assert second["stdout"] == first["stdout"]


def test_the_cache_is_scoped_to_one_run():
    """A global cache would let one report's snapshot leak into another's, and
    live state changes between them."""
    shared = _FakeRedis()
    a = cc.CloudContext(session=_FakeSession(), redis_client=shared, thread_id="RPT-a",
                        project_id=PROJECT, target_sa_email=SA)
    b = cc.CloudContext(session=_FakeSession(), redis_client=shared, thread_id="RPT-b",
                        project_id=PROJECT, target_sa_email=SA)
    a.run(binary="gcloud", args=["projects", "describe", PROJECT], why="x")
    b.run(binary="gcloud", args=["projects", "describe", PROJECT], why="x")
    assert len(b.session.calls) == 1


def test_a_failed_command_is_not_cached():
    """Caching a 503 would make it stick for the rest of the run, and the run is
    exactly the window in which a retry might work."""
    fail = CommandResult(ok=False, exit_code=1, stdout="", stderr="503",
                         truncated=False, duration_ms=5, command="x")
    ctx = context(results=[fail, fail])
    ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="x")
    ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="x")
    assert len(ctx.session.calls) == 2


def test_a_dead_cache_costs_money_and_time_never_correctness():
    ctx = context(redis=_FakeRedis(broken=True))
    result = ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="x")
    assert result["ok"] is True


# ── the evidence log ─────────────────────────────────────────────────────────


def test_every_attempt_is_recorded_with_a_citable_id():
    """Successes, refusals and failures alike. A report that quietly omits the
    command that failed is the report this feature exists to prevent."""
    ctx = context(results=[
        CommandResult(ok=False, exit_code=1, stdout="", stderr="denied",
                      truncated=False, duration_ms=1, command="x"),
    ])
    ctx.run(binary="gcloud", args=["compute", "instances", "delete", "x"], why="refused")
    ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="failed")
    ctx.run(binary="gcloud", args=["compute", "networks", "list", "--limit=5"], why="ran")

    assert [e["evidence_id"] for e in ctx.log] == ["E1", "E2", "E3"]
    assert [e["kind"] for e in ctx.log] == ["rejected", "ran", "ran"]
    assert all(e["why"] for e in ctx.log)


def test_the_why_the_caller_gave_is_kept_on_every_entry():
    ctx = context()
    ctx.run(binary="gcloud", args=["projects", "describe", PROJECT], why="confirm lifecycle state")
    assert ctx.log[0]["why"] == "confirm lifecycle state"


# ── the container slot ───────────────────────────────────────────────────────


def test_two_runs_cannot_exceed_the_configured_slot_count():
    """Celery slots cap *tasks*, not containers: one report holds one container
    for its whole investigation, so the cap has to be independent."""
    redis = _FakeRedis()
    first = cc.acquire_slot(redis, thread_id="RPT-a", limit=1)
    second = cc.acquire_slot(redis, thread_id="RPT-b", limit=1)
    assert first == "cli:slot:0"
    assert second is None


def test_a_released_slot_is_reusable():
    redis = _FakeRedis()
    key = cc.acquire_slot(redis, thread_id="RPT-a", limit=1)
    cc.release_slot(redis, key, thread_id="RPT-a")
    assert cc.acquire_slot(redis, thread_id="RPT-b", limit=1) == "cli:slot:0"


def test_a_run_cannot_release_a_slot_another_run_now_holds():
    """If ours expired and someone else took it, a blind DELETE would free their
    container's slot while their container is still running — and the cap would
    silently stop being a cap."""
    redis = _FakeRedis()
    redis.data["cli:slot:0"] = "RPT-someone-else"
    cc.release_slot(redis, "cli:slot:0", thread_id="RPT-a")
    assert redis.data["cli:slot:0"] == "RPT-someone-else"


def test_a_crashed_worker_cannot_leak_a_slot_permanently():
    """The TTL is the crash net: a SIGKILLed worker releases nothing, so without
    an expiry one dead run would hold a slot forever."""
    redis = _FakeRedis()
    recorded = {}
    redis.set = lambda k, v, nx=False, ex=None: recorded.update(ex=ex) or True
    cc.acquire_slot(redis, thread_id="RPT-a", limit=1)
    assert recorded["ex"] == cc.SLOT_TTL_SECONDS
    assert cc.SLOT_TTL_SECONDS > g.MAX_CLI_WALL_CLOCK_SECONDS


# ── the failure policy ───────────────────────────────────────────────────────


class _Settings(dict):
    redis_url = "redis://localhost:6379/0"


def test_the_kill_switch_yields_no_context_rather_than_raising():
    """Turning the feature off must produce the report the pipeline produced
    before it existed, plus a notice — with no schema change and no migration."""
    settings = _Settings(CLOUD_CLI_ENABLED="false", CLOUD_CLI_IMAGE=IMAGE_STUB)
    with cc.open_cloud_context(
        settings=settings, thread_id="RPT-off", project_id=PROJECT,
        target_sa_email=SA, redis_client=_FakeRedis(),
    ) as ctx:
        assert ctx is None


def test_no_free_slot_degrades_the_report_rather_than_failing_it():
    redis = _FakeRedis()
    redis.data["cli:slot:0"] = "RPT-someone-else"
    settings = _Settings(
        CLOUD_CLI_ENABLED="true", CLOUD_CLI_IMAGE=IMAGE_STUB,
        MAX_CONCURRENT_CLI_SESSIONS="1", DOCKER_HOST="unix:///x", GCLOUD_ADC_PATH="",
    )
    with cc.open_cloud_context(
        settings=settings, thread_id="RPT-b", project_id=PROJECT,
        target_sa_email=SA, redis_client=redis,
    ) as ctx:
        assert ctx is None


def test_a_token_that_cannot_be_minted_names_itself_and_does_not_fail_the_report(monkeypatch):
    """The worker lacking serviceAccountTokenCreator on the scanner SA is the
    likeliest cause, and it must reach the reader as a reason rather than as an
    empty section."""
    monkeypatch.setattr(
        cc, "access_token_for",
        lambda sa: (_ for _ in ()).throw(RuntimeError("caller does not have permission")),
    )
    settings = _Settings(
        CLOUD_CLI_ENABLED="true", CLOUD_CLI_IMAGE=IMAGE_STUB,
        MAX_CONCURRENT_CLI_SESSIONS="1", DOCKER_HOST="unix:///x", GCLOUD_ADC_PATH="",
    )
    with cc.open_cloud_context(
        settings=settings, thread_id="RPT-c", project_id=PROJECT,
        target_sa_email=SA, redis_client=_FakeRedis(),
    ) as ctx:
        assert ctx is None


def test_the_slot_is_released_even_when_the_context_could_not_open(monkeypatch):
    """Releasing last and unconditionally: a leaked slot with the feature broken
    would mean nobody gets live context until the TTL expires."""
    redis = _FakeRedis()
    monkeypatch.setattr(
        cc, "access_token_for", lambda sa: (_ for _ in ()).throw(RuntimeError("nope"))
    )
    settings = _Settings(
        CLOUD_CLI_ENABLED="true", CLOUD_CLI_IMAGE=IMAGE_STUB,
        MAX_CONCURRENT_CLI_SESSIONS="1", DOCKER_HOST="unix:///x", GCLOUD_ADC_PATH="",
    )
    with cc.open_cloud_context(
        settings=settings, thread_id="RPT-d", project_id=PROJECT,
        target_sa_email=SA, redis_client=redis,
    ):
        pass
    assert cc.acquire_slot(redis, thread_id="RPT-next", limit=1) == "cli:slot:0"


IMAGE_STUB = "google/cloud-sdk:583.0.0-slim"


# ── the registry ─────────────────────────────────────────────────────────────


def test_a_node_that_finds_no_registered_context_gets_none():
    """Which is what happens in tests, with the kill switch off, and on a
    resumed run in a process that never opened one."""
    assert cc.context_for("no-such-thread") is None
    assert cc.context_for(None) is None


def test_register_and_unregister_round_trip():
    ctx = context()
    cc.register("RPT-reg", ctx)
    assert cc.context_for("RPT-reg") is ctx
    cc.unregister("RPT-reg")
    assert cc.context_for("RPT-reg") is None
