"""Organization-level context.

The probe-then-degrade contract, the guard changes that make an org-scoped
command possible at all, and the one property that matters most: a report can
never read an organization other than its own project's parent.

**The positive path is covered here against a stub, not a cloud environment.**
A green run of this file proves only the boundary behavior exercised below.
"""

from __future__ import annotations

import pytest

from app.agents import recon_playbook, report_nodes
from app.integrations import cloud_cli_guards as g
from app.services import report_render

PROJECT = "synthetic-project-id"
SA = "scanner@synthetic-project.invalid"
ORG = "synthetic-organization-id"

# A representative synthetic project response.
PROJECT_STEP = {
    "ok": True,
    "evidence_id": "E1",
    "command": f"gcloud projects describe {PROJECT}",
    "data": {
        "name": PROJECT,
        "projectId": PROJECT,
        "lifecycleState": "ACTIVE",
        "parent": {"id": ORG, "type": "organization"},
    },
}


# ── reading the org id out of a step the run already made ───────────────────


def test_the_org_id_comes_from_the_project_step_with_no_extra_call():
    """`gcloud projects describe` is already playbook step 1 and already
    returns `parent`."""
    assert recon_playbook.organization_id_from(PROJECT_STEP) == ORG


def test_a_folder_parent_is_not_treated_as_an_organization():
    """Folder-scoped policy reads are a different flag and a different
    permission. Passing a folder id as an organization id produces a confusing
    'does not exist' instead of an honest 'not supported'."""
    step = {"ok": True, "data": {"parent": {"id": "99887766", "type": "folder"}}}
    assert recon_playbook.organization_id_from(step) is None


@pytest.mark.parametrize(
    "step",
    [
        None,
        {},
        {"ok": False, "error": "denied"},
        {"ok": True, "data": []},           # a list, which is what a `list` step returns
        {"ok": True, "data": {}},           # no parent at all
        {"ok": True, "data": {"parent": {"type": "organization"}}},  # no id
        {"ok": True, "text": "not json"},
    ],
)
def test_anything_without_an_organization_parent_yields_none(step):
    assert recon_playbook.organization_id_from(step) is None


# ── the guards: an org id is injected, never accepted ────────────────────────


@pytest.mark.parametrize(
    "flag",
    ["--organization=1234", "--organization-id=1234", "--folder=1234", "--folder-id=1234"],
)
def test_a_model_supplied_organization_is_refused(flag):
    """A caller must not choose an organization outside the report boundary."""
    with pytest.raises(g.GuardRejection) as exc:
        g.check_command(
            "gcloud",
            ["resource-manager", "org-policies", "list", flag, "--limit=10"],
            project_id=PROJECT,
            target_sa_email=SA,
        )
    assert exc.value.rejected_by == "G3_flags"
    assert "cannot be chosen" in exc.value.fix


def test_the_injected_organization_replaces_the_project_flag():
    """The bug that made every org command impossible. `gcloud resource-manager
    org-policies` accepts exactly one scope flag and answers two with a *usage*
    error, which reads like a malformed command."""
    checked = g.check_command(
        "gcloud",
        ["resource-manager", "org-policies", "list", "--format=json(constraint)", "--limit=100"],
        project_id=PROJECT,
        target_sa_email=SA,
        organization_id=ORG,
    )
    assert f"--organization={ORG}" in checked.argv
    assert not any(t.startswith("--project") for t in checked.argv)


def test_the_two_scope_flags_are_never_both_injected():
    """Stated as its own assertion because it is the actual failure, and a test
    that only checked for `--organization` would pass while the command still
    died."""
    checked = g.check_command(
        "gcloud",
        ["resource-manager", "org-policies", "list", "--limit=10"],
        project_id=PROJECT,
        target_sa_email=SA,
        organization_id=ORG,
    )
    scope_flags = [t for t in checked.argv if g.flag_name(t) in g.TARGET_FLAGS]
    assert len(scope_flags) == 1, scope_flags


def test_without_an_organization_id_the_project_is_still_injected():
    """The default path must be untouched: every non-org command in the
    playbook still gets `--project`."""
    checked = g.check_command(
        "gcloud",
        ["compute", "networks", "list", "--limit=10"],
        project_id=PROJECT,
        target_sa_email=SA,
    )
    assert f"--project={PROJECT}" in checked.argv
    assert not any(t.startswith("--organization") for t in checked.argv)


def test_the_positional_probe_keeps_the_project_flag():
    """`gcloud organizations describe <id>` takes the org as a positional and
    does not accept `--organization`. `--project` is a global flag and stays
    harmless — verified against the real API, which answered PERMISSION_DENIED
    rather than a usage error."""
    checked = g.check_command(
        "gcloud",
        recon_playbook.ORG_PROBE.render(PROJECT, ORG),
        project_id=PROJECT,
        target_sa_email=SA,
    )
    assert ORG in checked.argv
    assert f"--project={PROJECT}" in checked.argv


@pytest.mark.parametrize("step", recon_playbook.ORG_PLAYBOOK, ids=lambda s: s.key)
def test_every_org_step_survives_the_guard_chain(step):
    """A step the guards refuse is a step silently missing from every report.
    Mirrors the equivalent test for the project playbook."""
    g.check_command(
        step.binary,
        step.render(PROJECT, ORG),
        project_id=PROJECT,
        target_sa_email=SA,
        organization_id=ORG if step.org_scoped else None,
    )


def test_the_probe_is_not_organizations_list():
    """`organizations list` returns 11 orgs to this SA while `describe` on our
    own org is denied — so a probe built on it reports success and is wrong."""
    assert "list" not in recon_playbook.ORG_PROBE.args
    assert "describe" in recon_playbook.ORG_PROBE.args
    assert "{org}" in recon_playbook.ORG_PROBE.args


# ── the recon node ───────────────────────────────────────────────────────────


class _StubContext:
    """A CloudContext that answers the project playbook and lets the org path
    be steered independently."""

    def __init__(self, *, org_probe_ok: bool, org_failures: set[str] | None = None):
        self.org_probe_ok = org_probe_ok
        self.org_failures = org_failures or set()
        self.project_id = PROJECT
        self.organization_id: str | None = None
        self.log: list[dict] = []
        self.org_scoped_calls: list[list[str]] = []
        self.session = type(
            "S", (), {"commands_run": 0, "remaining_commands": lambda s, p=None: 9}
        )()

    def run(self, *, binary, args, why, pillar=None, org_scoped=False):
        joined = " ".join(args)
        if org_scoped:
            self.org_scoped_calls.append(args)
        if "organizations describe" in joined:
            ok, out = self.org_probe_ok, '{"name": "organizations/%s"}' % ORG
        elif "projects describe" in joined:
            ok, out = True, '{"parent": {"id": "%s", "type": "organization"}}' % ORG
        else:
            ok = not any(f in joined for f in self.org_failures)
            out = '[{"constraint": "constraints/storage.publicAccessPrevention"}]'
        entry = {
            "ok": ok,
            "command": f"{binary} {joined}",
            "why": why,
            "evidence_id": f"E{len(self.log) + 1}",
            "stdout": out if ok else "",
            "stderr": "" if ok else "ERROR: PERMISSION_DENIED: getOrgPolicy",
            "kind": "ran",
        }
        self.log.append(entry)
        return entry


def _recon(monkeypatch, ctx):
    monkeypatch.setattr(report_nodes.cloud_context, "context_for", lambda t: ctx)
    return report_nodes.recon({"graph_thread_id": "RPT-x", "project_id": PROJECT})


def test_a_denied_probe_records_the_reason_and_runs_no_org_command(monkeypatch):
    """The case that actually happens today. The run continues, the org
    playbook does not execute, and the denial is kept verbatim."""
    ctx = _StubContext(org_probe_ok=False)
    out = _recon(monkeypatch, ctx)

    assert out["org_context_status"] == "unavailable"
    assert "PERMISSION_DENIED" in out["org_context_reason"]
    assert ctx.org_scoped_calls == []
    assert ctx.organization_id is None


def test_a_denied_probe_does_not_make_the_report_partial(monkeypatch):
    """Denial is the expected case. Letting it mark every report `partial`
    would drain that word of the meaning it has for project recon."""
    out = _recon(monkeypatch, _StubContext(org_probe_ok=False))
    assert out["live_context_status"] == "complete"
    assert out["live_context_reason"] is None


def test_a_passing_probe_runs_the_org_playbook(monkeypatch):
    ctx = _StubContext(org_probe_ok=True)
    out = _recon(monkeypatch, ctx)

    assert out["org_context_status"] == "available"
    assert out["org_context_reason"] is None
    assert ctx.organization_id == ORG
    for step in recon_playbook.ORG_PLAYBOOK:
        assert step.key in out["live_snapshot"]


def test_the_org_id_is_only_trusted_after_the_probe_passes(monkeypatch):
    """`organization_id` is what G5 injects, so setting it before the probe
    would scope commands to an org this run has no answer about."""
    ctx = _StubContext(org_probe_ok=False)
    _recon(monkeypatch, ctx)
    assert ctx.organization_id is None


def test_a_failing_org_step_is_reported_without_losing_the_others(monkeypatch):
    ctx = _StubContext(org_probe_ok=True, org_failures={"access-context-manager"})
    out = _recon(monkeypatch, ctx)

    assert out["org_context_status"] == "available"
    assert "vpc_sc_policies" in out["org_context_reason"]
    assert out["live_snapshot"]["vpc_sc_policies"]["ok"] is False
    assert out["live_snapshot"]["org_policies"]["ok"] is True
    # and it still does not touch the project-level status
    assert out["live_context_status"] == "complete"


def test_a_folder_parent_reports_not_applicable_and_probes_nothing(monkeypatch):
    class _Folder(_StubContext):
        def run(self, *, binary, args, why, pillar=None, org_scoped=False):
            entry = super().run(binary=binary, args=args, why=why, pillar=pillar,
                                org_scoped=org_scoped)
            if "projects describe" in " ".join(args):
                entry["stdout"] = '{"parent": {"id": "42", "type": "folder"}}'
            return entry

    ctx = _Folder(org_probe_ok=True)
    out = _recon(monkeypatch, ctx)
    assert out["org_context_status"] == "not_applicable"
    assert not any("organizations describe" in e["command"] for e in ctx.log)


def test_the_probe_is_charged_to_no_pillar(monkeypatch):
    """Same reasoning as the project playbook: the probe is not any pillar's
    work, and charging it to one leaves that pillar a smaller allowance for a
    reason nobody could see."""
    ctx = _StubContext(org_probe_ok=True)
    _recon(monkeypatch, ctx)
    assert ctx.org_scoped_calls, "the org playbook should have run"


# ── what the reader is told ──────────────────────────────────────────────────


def _note(status, reason=None, base_status="complete"):
    return report_render.live_context_note(
        {
            "status": base_status,
            "reason": None,
            "command_log": [{"kind": "ran"}],
            "organization": {"status": status, "reason": reason},
        }
    )


def test_the_banner_says_org_policy_was_not_readable():
    """An org policy can override a project finding — PAP enforced at the org
    makes a public-bucket finding moot — so a reader who is not told cannot
    tell 'looked and found nothing' from 'could not look'."""
    note = _note("unavailable", "PERMISSION_DENIED: getOrgPolicy")
    assert "Organization-level policy was not readable" in note
    assert "PERMISSION_DENIED" in note
    assert "already be prevented by a policy this report could not see" in note


def test_the_banner_says_so_when_org_policy_was_read():
    assert "Organization-level policy was also read" in _note("available")


def test_the_banner_stays_quiet_when_there_is_no_organization():
    """A project under a folder has no organization policy to report on, and a
    sentence about a thing that does not exist is noise."""
    assert "Organization" not in _note("not_applicable")


def test_a_standard_report_still_says_nothing_at_all():
    """`live_context_note(None)` is a standard-mode report: it never claimed to
    have looked, and must not start claiming anything now."""
    assert report_render.live_context_note(None) == ""


def test_an_older_report_is_not_described_as_denied():
    """A checkpoint written before the org-context probe existed did not probe and was not
    refused. Reporting a denial that never happened is the same dishonesty the
    banner exists to prevent."""
    bundle = report_nodes.live_context_of({"live_context_status": "complete"})
    assert bundle["organization"]["status"] == "not_applicable"
    assert "Organization" not in report_render.live_context_note(bundle)


# ── the two bundle builders must not drift ───────────────────────────────────


def test_both_live_context_builders_agree_on_their_keys():
    """`report_nodes.live_context_of` reads graph state mid-run and
    `worker.tasks._live_context_of` reads the final state; the duplication is
    deliberate and documented on both.

    If the node grows an `organization` key while the worker does not, the
    renderer and stored row disagree without an obvious failure.
    """
    from app.worker import tasks

    final = {
        "live_context_status": "complete",
        "live_context_reason": None,
        "live_snapshot": {"project": {}},
        "command_log": [{"kind": "ran"}],
        "org_context_status": "unavailable",
        "org_context_reason": "PERMISSION_DENIED",
    }
    assert set(tasks._live_context_of(final)) == set(report_nodes.live_context_of(final))


def test_the_stored_row_carries_the_org_verdict():
    from app.worker import tasks

    bundle = tasks._live_context_of(
        {"org_context_status": "unavailable", "org_context_reason": "PERMISSION_DENIED"}
    )
    assert bundle["organization"] == {
        "status": "unavailable",
        "reason": "PERMISSION_DENIED",
    }


def test_a_pre_ticket_run_stores_not_applicable_rather_than_denied():
    from app.worker import tasks

    assert tasks._live_context_of({})["organization"]["status"] == "not_applicable"


# ── the banner is customer-facing prose, not a log line ──────────────────────

GCLOUD_DENIAL = (
    "ERROR: (gcloud.organizations.describe) [None] does not have permission to "
    "access organizations instance [synthetic-organization-id] (or it may not exist): The caller "
    "does not have permission. This command is authenticated with an access token "
    "from the CLOUDSDK_AUTH_ACCESS_TOKEN environment variable"
)


def test_the_banner_drops_gcloud_s_auth_boilerplate():
    """gcloud's auth boilerplate tells a reader nothing about their cloud and
    names one of our environment variables in a document we hand to a customer."""
    note = _note("unavailable", GCLOUD_DENIAL)
    assert "CLOUDSDK_AUTH_ACCESS_TOKEN" not in note
    assert "authenticated with an access token" not in note


def test_the_banner_keeps_the_part_that_says_what_went_wrong():
    """Trimmed, not flattened — 'was not allowed to look' has to survive."""
    note = _note("unavailable", GCLOUD_DENIAL)
    assert "does not have permission" in note
    assert "synthetic-organization-id" in note


def test_the_stored_reason_is_not_trimmed():
    """The appendix is where a disputed sentence gets settled, so the row keeps
    the error byte-for-byte."""
    from app.worker import tasks

    stored = tasks._live_context_of({
        "org_context_status": "unavailable", "org_context_reason": GCLOUD_DENIAL,
    })
    assert stored["organization"]["reason"] == GCLOUD_DENIAL


def test_a_reason_that_is_only_boilerplate_still_says_something():
    """Splitting on the boilerplate must not leave an empty reason and a
    dangling colon."""
    note = _note("unavailable", "This command is authenticated with an access token blah")
    assert note.strip().endswith(".")
    assert ": ." not in note
