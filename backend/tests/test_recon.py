"""The recon node, the playbook, and what the reader is told.

The node is exercised against a stubbed `CloudContext` rather than a container,
because what matters here is the *status* contract: every outcome is a status
the document then states on its face, and none of them fails the report.
"""

from __future__ import annotations

import pytest

from app.agents import cloud_context as cc
from app.agents import recon_playbook, report_nodes, skills
from app.integrations import cloud_cli_guards as g
from app.services import report_render

PROJECT = "synthetic-project-id"
SA = "scanner@synthetic-project.invalid"


# ── the playbook ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("step", recon_playbook.PLAYBOOK, ids=lambda s: s.key)
def test_every_playbook_step_survives_the_guard_chain(step):
    """A step the guards refuse is a step silently missing from every report's
    live context. `gcloud run services list` failed exactly this way — `run` is
    on the write denylist — and nothing but this test would have said so."""
    g.check_command(
        step.binary,
        step.render(PROJECT),
        project_id=PROJECT,
        target_sa_email=SA,
    )


def test_every_step_carries_a_reduction_flag_or_needs_none():
    """G4 enforces it, but a step that trips G4 is a bug in the playbook rather
    than something for the guard to catch at runtime."""
    for step in recon_playbook.PLAYBOOK:
        args = step.render(PROJECT)
        verb = g.verb_of(args, allowed=g.READ_VERBS if step.binary == "gcloud" else g.BQ_VERBS)
        if verb in g.VERBS_NEEDING_REDUCTION:
            assert any(g.flag_name(t) in g.REDUCING_FLAGS for t in args if t.startswith("-"))


def test_every_step_says_why_it_runs():
    """`why` reaches the customer-facing evidence appendix, so an empty one is a
    blank cell in a document a customer reads."""
    for step in recon_playbook.PLAYBOOK:
        assert step.why and step.why[0].islower()


def test_the_two_highest_yield_calls_are_fixed_steps_not_discoveries():
    """Public-binding search and dataset metadata are fixed safeguards."""
    keys = {s.key for s in recon_playbook.PLAYBOOK}
    assert "public_iam_bindings" in keys
    assert "datasets" in keys


def test_the_project_positional_is_substituted_not_left_as_a_placeholder():
    """`gcloud projects describe` takes the project as a *positional*; the
    injected `--project` flag sets the quota project and does not fill it."""
    step = next(s for s in recon_playbook.PLAYBOOK if s.key == "project")
    assert step.render(PROJECT) == ["projects", "describe", PROJECT]


# ── the node's status contract ───────────────────────────────────────────────


class _StubContext:
    def __init__(self, failing: set[str] | None = None):
        self.failing = failing or set()
        self.log: list[dict] = []
        self.session = type("S", (), {"commands_run": 0, "remaining_commands": lambda s, p=None: 9})()

    def run(self, *, binary, args, why, pillar=None):
        key = " ".join(args)
        ok = not any(f in key for f in self.failing)
        entry = {
            "ok": ok, "command": f"{binary} {key}", "why": why,
            "evidence_id": f"E{len(self.log) + 1}",
            "stdout": '[{"name": "x"}]' if ok else "",
            "stderr": "" if ok else "ERROR: permission denied",
            "kind": "ran",
        }
        self.log.append(entry)
        return entry


def run_recon(monkeypatch, ctx):
    monkeypatch.setattr(report_nodes.cloud_context, "context_for", lambda t: ctx)
    return report_nodes.recon({"graph_thread_id": "RPT-x", "project_id": PROJECT})


def test_a_clean_run_reports_complete(monkeypatch):
    out = run_recon(monkeypatch, _StubContext())
    assert out["live_context_status"] == "complete"
    assert out["live_context_reason"] is None
    assert len(out["live_snapshot"]) == len(recon_playbook.PLAYBOOK)


def test_a_partly_failing_run_reports_partial_and_names_what_failed(monkeypatch):
    out = run_recon(monkeypatch, _StubContext(failing={"search-all-iam-policies"}))
    assert out["live_context_status"] == "partial"
    assert "public_iam_bindings" in out["live_context_reason"]
    # The failure is still in the snapshot, with its error, rather than absent.
    assert out["live_snapshot"]["public_iam_bindings"]["ok"] is False
    assert "permission denied" in out["live_snapshot"]["public_iam_bindings"]["error"]


def test_no_container_reports_unavailable_and_does_not_raise(monkeypatch):
    """Deep mode shipped and was correct before live context existed. Failing a
    customer-facing document because the Cloud Asset API is disabled on one
    project would be a regression against a pipeline that works."""
    monkeypatch.setattr(report_nodes.cloud_context, "context_for", lambda t: None)
    out = report_nodes.recon({"graph_thread_id": "RPT-x", "project_id": PROJECT})
    assert out["live_context_status"] == "unavailable"
    assert out["live_context_reason"]
    assert out["live_snapshot"] == {}


def test_a_failed_step_keeps_its_stderr_verbatim(monkeypatch):
    """The distinction between "there are no org policies" and "we were not
    allowed to look" is the most important thing this node reports, and a
    flattened "failed" destroys it."""
    out = run_recon(monkeypatch, _StubContext(failing={"buckets"}))
    entry = out["live_snapshot"]["buckets"]
    assert entry["error"] == "ERROR: permission denied"
    assert entry["evidence_id"]


def test_the_command_log_carries_every_attempt(monkeypatch):
    out = run_recon(monkeypatch, _StubContext(failing={"buckets"}))
    assert len(out["command_log"]) == len(recon_playbook.PLAYBOOK)


def test_json_output_is_parsed_so_the_model_reasons_over_structure(monkeypatch):
    out = run_recon(monkeypatch, _StubContext())
    assert out["live_snapshot"]["networks"]["data"] == [{"name": "x"}]


# ── what the reader is told ──────────────────────────────────────────────────


def test_a_complete_report_still_says_its_live_context_was_complete():
    """A notice that appears only on failure trains a reader to skim past its
    absence — and absence is exactly the case they cannot otherwise detect."""
    note = report_render.live_context_note(
        {"status": "complete", "command_log": [{"kind": "ran"}, {"kind": "ran"}]}
    )
    assert "checked against the project's live state" in note
    assert "2 read-only commands ran" in note


def test_an_unavailable_report_says_so_on_its_face_and_names_the_reason():
    note = report_render.live_context_note(
        {"status": "unavailable", "reason": "the Cloud Asset API is disabled"}
    )
    assert "Live context unavailable" in note
    assert "the Cloud Asset API is disabled" in note
    assert "latent misconfiguration cannot be told apart" in note


def test_a_partial_report_says_which_checks_went_unverified():
    note = report_render.live_context_note(
        {"status": "partial", "reason": "1 of 11 playbook steps failed: buckets"}
    )
    assert "partly" in note
    assert "buckets" in note
    assert "unverified" in note


def test_a_standard_report_says_nothing_because_it_never_claimed_to_look():
    assert report_render.live_context_note(None) == ""
    assert report_render.live_context_note({}) == ""


def test_the_banner_sits_above_the_executive_summary():
    """It is a caveat on the sentence a reader acts on, not a footnote to it."""
    lines = report_render._live_context_banner({"status": "unavailable", "reason": "off"})
    assert lines[0].startswith("> **Live context:**")


# ── the skill ────────────────────────────────────────────────────────────────


def test_the_skill_says_nothing_about_mutation_workflow_or_asking_a_human():
    """Upstream's plan template, dry-run workflow and authorization prose are
    irrelevant at best and contradictory at worst — there is no user to ask."""
    text = skills.GCLOUD.lower()
    for absent in ("--dry-run", "--validate-only", "authorization", "mcp", "--async"):
        assert absent not in text


def test_the_skill_teaches_the_rules_the_guards_enforce():
    text = skills.GCLOUD
    assert "--limit" in text and "--filter" in text and "--format" in text
    assert "gcloud help" in text
    assert "INFORMATION_SCHEMA" in text
    # The BigQuery route the skill teaches has to be the one that actually
    # works: `bq show` for volumes, and backticks where BigQuery requires them.
    # Teaching the unquoted form would produce an invalid command.
    assert "bq show" in text
    assert "Backticks are required here" in text
    assert "TABLE_STORAGE` will not work" in text


def test_the_skill_tells_the_agent_the_project_and_identity_are_supplied():
    assert "--project" in skills.GCLOUD
    assert "supplied for you" in skills.GCLOUD


def test_the_skill_carries_the_reconciliation_patterns():
    text = skills.GCLOUD
    assert "STOPPED" in text
    assert "Public Access Prevention" in text
    assert "Volume can change the priority" in text


def test_the_skill_is_read_once_and_is_stable():
    """It sits in the system prefix, so a byte that varies per call costs the
    prefix cache for itself and everything after it."""
    assert skills.load("gcloud") is skills.load("gcloud")
    assert skills.GCLOUD == skills.load("gcloud")


# ── the tool declaration ─────────────────────────────────────────────────────


def test_the_tool_has_no_project_or_identity_parameter():
    """The same assertion `test_agent_tools` makes about `project_id`: a
    hallucinated project cannot be passed because there is nowhere to pass it.
    A boundary, not a filter."""
    params = report_nodes.RUN_CLOUD_COMMAND_DECLARATION["parameters"]["properties"]
    for forbidden in ("project", "project_id", "impersonate_service_account", "account"):
        assert forbidden not in params
    assert set(params) == {"binary", "args", "why"}


def test_the_tool_requires_a_reason():
    """It costs the model a sentence and gives the trace and the customer-facing
    evidence appendix a reason for every command run against a customer's
    project."""
    assert "why" in report_nodes.RUN_CLOUD_COMMAND_DECLARATION["parameters"]["required"]


def test_the_binary_is_an_enum_not_free_text():
    binary = report_nodes.RUN_CLOUD_COMMAND_DECLARATION["parameters"]["properties"]["binary"]
    assert binary["enum"] == ["gcloud", "bq"]


def test_the_tool_is_only_offered_when_a_container_is_actually_open():
    """Declaring it against a run with no live context spends prefix bytes
    teaching a tool whose every call returns "unavailable", and invites the
    model to keep trying."""
    without = {d["name"] for d in report_nodes.read_only_declarations()}
    with_cloud = {d["name"] for d in report_nodes.read_only_declarations(with_cloud=True)}
    assert "run_cloud_command" not in without
    assert "run_cloud_command" in with_cloud
    assert with_cloud - without == {"run_cloud_command"}


def test_no_write_tool_is_ever_offered_to_the_investigator():
    """Unchanged, asserted because the declaration list grew."""
    from app.services import agent_tools

    offered = {d["name"] for d in report_nodes.read_only_declarations(with_cloud=True)}
    assert not (offered & agent_tools.WRITE_TOOLS)


def test_the_command_log_accumulates_across_the_run_rather_than_being_replaced():
    """`recon` writes the playbook and every `investigate_pillar` adds the
    follow-ups it chose. A plain channel keeps only the last writer's slice, so
    the appendix would show the playbook and none of the investigation — the
    half a reader can already guess, and not the half they cannot.

    The command log must retain both fixed and follow-up commands."""
    import operator
    from typing import get_args, get_type_hints

    from app.agents.report_state import ReportGraphState

    hint = get_type_hints(ReportGraphState, include_extras=True)["command_log"]
    assert operator.add in get_args(hint)


def test_a_pillar_returns_only_the_entries_it_added():
    """With an appending reducer, returning the whole shared log from every
    pillar multiplies the evidence appendix by the pillar count."""
    import inspect

    source = inspect.getsource(report_nodes.investigate_pillar)
    assert "cloud.log[log_start:]" in source
