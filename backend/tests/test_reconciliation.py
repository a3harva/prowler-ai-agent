"""What live state says about each finding, and the gates that hold it.

Everything under test here is pure: the coercion, gates C6/C7/C8, and both
renderers take a plain dict and return a document. No database, no Docker, no
model — the same discipline `test_report_ledger.py` and `test_cloud_cli_guards.py`
keep, and for the same reason: a reconciliation tested through a stub is
deterministic rather than dependent on a model response.

This suite tests behavior against representative inputs; it does not make
claims about any external project's current state.
"""

from __future__ import annotations

import pytest

from app.agents import report_nodes as nodes
from app.agents.report_artifacts import NOT_INVESTIGATED, coerce_reconciliation
from app.agents.report_ledger import (
    build_index,
    digest,
    evidence_section_of,
    parse_rendered,
    verify_artifacts,
    verify_document,
)
from app.services.report_pdf import render_pdf_html
from app.services.report_render import render_markdown, validate_markdown

SECURITY = "Security, Privacy & Compliance"
OPS = "Operational Excellence"


def _group(check_id, *, severity="high", resources=2, service="iam"):
    return {
        "check_id": check_id,
        "check_title": f"Title for {check_id}",
        "severity": severity,
        "service_name": service,
        "categories": "identity-access",
        "description": f"description of {check_id}",
        "risk": f"risk of {check_id}",
        "remediation_text": "Do the thing.",
        "remediation_cli": "gcloud projects remove-iam-policy-binding x --member y",
        "remediation_terraform": 'resource "google_project_iam_binding" "x" {}',
        "resources": [
            {
                "resource_name": f"{check_id}-resource-{i}",
                "region": "global",
                "status_extended": f"{check_id} failed on resource {i}",
                "muted": False,
                "mute_reason": None,
            }
            for i in range(resources)
        ],
    }


@pytest.fixture()
def payload():
    return {
        "pillars": {
            SECURITY: [
                _group("sql_public", severity="critical", resources=1, service="cloudsql"),
                _group("bq_no_cmek", severity="high", resources=6, service="bigquery"),
            ],
            OPS: [_group("logging_disabled", severity="medium", service="logging")],
        },
        "skipped_finding_count": 0,
        "unknown_category_count": 0,
        "muted_excluded_count": 0,
        "severity_counts": {
            SECURITY: {"critical": 1, "high": 1},
            OPS: {"medium": 1},
        },
    }


@pytest.fixture()
def index(payload):
    return build_index(payload)


# The two commands the reference project's own report cites, plus one that was
# refused — a rejection is evidence, and a log with only successes in it would
# never exercise the appendix's failure path.
COMMAND_LOG = [
    {
        "evidence_id": "E1",
        "kind": "ran",
        "ok": True,
        "command": "gcloud sql instances list --format=json",
        "why": "check whether the flagged database is actually running",
        "at": 1_756_900_000.0,
        "exit_code": 0,
        "stdout": '[{"name": "itsm-database", "state": "STOPPED"}]',
    },
    {
        "evidence_id": "E2",
        "kind": "ran",
        "ok": True,
        "command": "bq show --format=json sample_audit_dataset.sample_incident",
        "why": "size the data the missing encryption key would have protected",
        "at": 1_756_900_030.0,
        "exit_code": 0,
        "stdout": '{"numRows": "100"}',
    },
    {
        "evidence_id": "E3",
        "kind": "rejected",
        "ok": False,
        "command": "bq tables list sample_audit_dataset",
        "reason": "'tables' is not a permitted bq verb",
        "why": "list the tables in the dataset",
        "at": 1_756_900_060.0,
    },
    {
        "evidence_id": "E4",
        "kind": "ran",
        "ok": False,
        "command": "gcloud resource-manager org-policies list --organization=1234",
        "why": "read the org-level policies",
        "at": 1_756_900_090.0,
        "exit_code": 1,
        "stderr": "PERMISSION_DENIED: caller lacks orgpolicy.policy.get",
    },
]

EVIDENCE_IDS = {"E1", "E2", "E3", "E4"}


def _reconciliation():
    return {
        "sql_public": {
            "verdict": "moot",
            "statement": "The database is stopped and has no public endpoint, so the "
            "exposure cannot occur while it stays that way.",
            "evidence": ["E1"],
        },
        "bq_no_cmek": {
            "verdict": "amplifies",
            "statement": "The unencrypted dataset holds the support-ticket history, "
            "which is the largest store of customer data in the project.",
            "evidence": ["E2"],
        },
        "logging_disabled": {
            "verdict": "no_evidence",
            "statement": NOT_INVESTIGATED,
            "evidence": [],
        },
    }


def _artifacts(index):
    return {
        "check_analysis": {
            c: {"explanation": f"What {c} means.", "why_here": f"Why {c} matters here."}
            for c in index
        },
        "pillar_analysis": {
            SECURITY: {"narrative": "Security narrative.", "analysis": "Security analysis."},
            OPS: {"narrative": "Ops narrative.", "analysis": "Ops analysis."},
        },
        "themes": [
            {
                "title": "Data stores without their own controls",
                "narrative": "Two checks trace to the same unmanaged data path.",
                "refs": ["sql_public", "bq_no_cmek"],
            }
        ],
        "remediation_plan": [
            {
                "label": "Close the data exposure",
                "rationale": "Do these first.",
                "refs": ["sql_public", "bq_no_cmek"],
            },
            {
                "label": "Restore audit coverage",
                "rationale": "Then this.",
                "refs": ["logging_disabled"],
            },
        ],
        "executive_summary": "Three open issues across two pillars.",
    }


def _render(payload, index, *, reconciliation=None, live_context=None):
    art = _artifacts(index)
    return render_markdown(
        project_id="synthetic-project-id",
        scan_id=7,
        payload=payload,
        narratives={p: e["narrative"] for p, e in art["pillar_analysis"].items()},
        explanations={c: e["explanation"] for c, e in art["check_analysis"].items()},
        executive_summary=art["executive_summary"],
        analysis={
            "themes": art["themes"],
            "remediation_plan": art["remediation_plan"],
            "pillar_analysis": {p: e["analysis"] for p, e in art["pillar_analysis"].items()},
            "check_context": {c: e["why_here"] for c, e in art["check_analysis"].items()},
            "reconciliation": reconciliation if reconciliation is not None else {},
        },
        live_context=live_context,
    )


def _live_context(status="complete"):
    return {"status": status, "reason": None, "snapshot": {}, "command_log": COMMAND_LOG}


# ── coercion ─────────────────────────────────────────────────────────────────


def test_a_check_the_model_said_nothing_about_is_visibly_not_investigated(index):
    out = coerce_reconciliation({"verdicts": []}, set(index))
    assert set(out) == set(index), "every ledger check must carry a verdict"
    assert all(e["verdict"] == "no_evidence" for e in out.values())
    assert out["sql_public"]["statement"] == NOT_INVESTIGATED


def test_a_verdict_for_a_check_outside_the_ledger_is_dropped(index):
    out = coerce_reconciliation(
        {
            "verdicts": [
                {"check_id": "not_in_this_project", "verdict": "confirms",
                 "statement": "x", "evidence": ["E1"]}
            ]
        },
        set(index),
    )
    assert "not_in_this_project" not in out


def test_an_unrecognised_verdict_falls_back_to_no_evidence(index):
    out = coerce_reconciliation(
        {
            "verdicts": [
                {"check_id": "sql_public", "verdict": "probably_fine",
                 "statement": "x", "evidence": ["E1"]}
            ]
        },
        set(index),
    )
    assert out["sql_public"]["verdict"] == "no_evidence"


def test_an_invented_evidence_id_survives_coercion_so_the_gate_can_name_it(index):
    """Deliberately unlike `_refs`, which filters unknown check_ids out.

    A citation is only printed, never indexed into, so keeping it costs
    nothing and lets C7 report the fabricated id rather than the vaguer
    "this verdict cites nothing".
    """
    out = coerce_reconciliation(
        {
            "verdicts": [
                {"check_id": "sql_public", "verdict": "moot",
                 "statement": "x", "evidence": ["E99"]}
            ]
        },
        set(index),
    )
    assert out["sql_public"]["evidence"] == ["E99"]


# ── C7 ───────────────────────────────────────────────────────────────────────


def _verify(index, *, reconciliation, evidence_ids=EVIDENCE_IDS):
    return verify_artifacts(index=index, evidence_ids=evidence_ids,
                            reconciliation=reconciliation, **_artifacts(index))


def test_a_sound_reconciliation_passes_every_artifact_gate(index):
    assert _verify(index, reconciliation=_reconciliation()) == []


def test_a_verdict_that_cites_nothing_fails_and_is_repairable(index):
    reconciliation = _reconciliation()
    reconciliation["sql_public"]["evidence"] = []
    failures = _verify(index, reconciliation=reconciliation)
    assert [f.gate for f in failures] == ["C7"]
    assert "sql_public" in failures[0].detail
    assert failures[0].repair_targets == ("reconciliation",)


def test_no_evidence_is_allowed_to_cite_nothing(index):
    """The one verdict that is the absence of evidence.

    Without this carve-out the honest answer is unprintable, and a model with
    a gate to satisfy would reach for `confirms` instead — which is the exact
    failure the section exists to prevent.
    """
    reconciliation = _reconciliation()
    assert reconciliation["logging_disabled"]["evidence"] == []
    assert _verify(index, reconciliation=reconciliation) == []


def test_a_citation_that_never_ran_fails_and_names_the_id(index):
    reconciliation = _reconciliation()
    reconciliation["bq_no_cmek"]["evidence"] = ["E2", "E77"]
    failures = _verify(index, reconciliation=reconciliation)
    assert [f.gate for f in failures] == ["C7"]
    assert "E77" in failures[0].detail
    assert "E2" not in failures[0].detail, "the good citation must not be blamed"


def test_a_verdict_for_a_check_outside_the_ledger_fails(index):
    reconciliation = _reconciliation()
    reconciliation["not_in_this_project"] = {
        "verdict": "confirms", "statement": "x", "evidence": ["E1"]
    }
    failures = _verify(index, reconciliation=reconciliation)
    assert [f.gate for f in failures] == ["C7"]
    assert "not_in_this_project" in failures[0].detail


def test_a_run_with_no_evidence_at_all_still_passes(index):
    """`unavailable` recon: every verdict is `no_evidence` and nothing fails."""
    reconciliation = coerce_reconciliation({}, set(index))
    assert _verify(index, reconciliation=reconciliation, evidence_ids=set()) == []


# ── C6, extended rather than relaxed ─────────────────────────────────────────


def test_a_command_in_a_live_state_statement_still_fails_c6(index):
    reconciliation = _reconciliation()
    reconciliation["sql_public"]["statement"] = (
        "Run gcloud sql instances patch itsm-database --no-assign-ip to fix this."
    )
    failures = _verify(index, reconciliation=reconciliation)
    assert [f.gate for f in failures] == ["C6"]
    assert failures[0].repair_targets == ("reconciliation",)


def test_the_appendix_may_print_a_command_that_actually_ran(payload, index):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    assert verify_document(index=index, payload=payload, content=content,
                           ledger_digest=digest(payload), command_log=COMMAND_LOG) == []


def test_the_appendix_may_not_print_a_command_that_did_not_run(payload, index):
    """The strengthening. A renderer that invents a command is a fatal defect —
    the appendix is the one place in the document a reader will trust a command
    to be a record of fact rather than a suggestion."""
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    content = content.replace(
        "gcloud sql instances list --format=json",
        "gcloud sql instances delete itsm-database",
    )
    failures = verify_document(index=index, payload=payload, content=content,
                               ledger_digest=digest(payload), command_log=COMMAND_LOG)
    assert [f.gate for f in failures] == ["C6"]
    assert "delete" in failures[0].detail
    assert failures[0].repair_targets == (), "a renderer defect is not repairable by prose"


def test_prowlers_own_remediation_commands_are_not_scanned_as_appendix_commands(
    payload, index
):
    """The body legitimately carries `gcloud` from the scan row, in fences.

    C6's document half looks only inside the appendix for exactly this reason;
    widening it to the whole document would fail every report ever generated.
    """
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    assert "gcloud projects remove-iam-policy-binding" in content
    assert (
        "gcloud projects remove-iam-policy-binding"
        not in evidence_section_of(content)
    )
    assert verify_document(index=index, payload=payload, content=content,
                           ledger_digest=digest(payload), command_log=COMMAND_LOG) == []


# ── C8 ───────────────────────────────────────────────────────────────────────


def test_a_ledger_that_moved_after_recon_fails_the_document(payload, index):
    frozen = digest(payload)
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    payload["pillars"][OPS][0]["resources"].pop()
    payload["severity_counts"][OPS]["medium"] = 0

    failures = verify_document(index=index, payload=payload, content=content,
                               ledger_digest=frozen, command_log=COMMAND_LOG)
    assert "C8" in [f.gate for f in failures]
    assert all(f.repair_targets == () for f in failures), "C8 is fatal, not repairable"


def test_c8_is_quiet_when_the_ledger_is_untouched(payload, index):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    failures = verify_document(index=index, payload=payload, content=content,
                               ledger_digest=digest(payload), command_log=COMMAND_LOG)
    assert failures == [], "the negative control — C8 must not fire on a sound run"


# ── the counts must not move ─────────────────────────────────────────────────


def _summary_table_of(content: str) -> list[str]:
    lines = content.splitlines()
    start = lines.index("## Pillar Summary")
    rows = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        if line.startswith("|"):
            rows.append(line)
    return rows


def test_live_context_changes_no_number_in_the_summary_table(payload, index):
    without = _render(payload, index)
    with_live = _render(payload, index, reconciliation=_reconciliation(),
                        live_context=_live_context())
    assert _summary_table_of(with_live) == _summary_table_of(without)


def test_live_context_changes_no_check_section_and_no_resource_row(payload, index):
    without = parse_rendered(_render(payload, index))
    with_live = parse_rendered(
        _render(payload, index, reconciliation=_reconciliation(),
                live_context=_live_context())
    )
    assert with_live["pillars"] == without["pillars"]
    assert with_live["resource_rows"] == without["resource_rows"]
    assert with_live["severity_table"] == without["severity_table"]


def test_the_new_sections_are_not_read_as_pillars(payload, index):
    """If they were, C4 would fail the report for a pillar the ledger has never
    heard of — and the frontend's table of contents would list them."""
    parsed = parse_rendered(
        _render(payload, index, reconciliation=_reconciliation(),
                live_context=_live_context())
    )
    assert set(parsed["pillars"]) == {SECURITY, OPS}


# ── what the reader sees ─────────────────────────────────────────────────────


def test_every_finding_carries_a_live_state_line_including_the_uninvestigated_one(
    payload, index
):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    assert "**Live context — No longer applicable** · evidence `E1`" in content
    assert "**Live context — Raised by live state** · evidence `E2`" in content
    assert "**Live context — Not checked against live state**" in content
    assert content.count("**Live context — ") == 3


def test_reduced_and_raised_findings_are_grouped_for_the_reader(payload, index):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    assert "## Live-State Reconciliation" in content
    assert "### Findings live state has reduced or closed" in content
    assert "### Findings live state has raised" in content
    reduced = content.split("### Findings live state has reduced or closed")[1].split(
        "### Findings live state has raised"
    )[0]
    assert "`sql_public`" in reduced
    assert "`bq_no_cmek`" not in reduced


def test_a_report_where_nothing_changed_renders_no_reconciliation_section(payload, index):
    """`confirms` and `no_evidence` are on every finding's own line already.

    Repeating three hundred confirmed checks in a second table would bury the
    handful that can actually be closed, which is the one conclusion the
    section exists to hand the reader."""
    reconciliation = {
        c: {"verdict": "confirms", "statement": "Still true.", "evidence": ["E1"]}
        for c in index
    }
    content = _render(payload, index, reconciliation=reconciliation,
                      live_context=_live_context())
    assert "## Live-State Reconciliation" not in content
    assert "**Live context — Confirmed against live state**" in content


def test_the_appendix_lists_every_command_including_the_ones_that_did_not_work(
    payload, index
):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    appendix = evidence_section_of(content)
    for entry in COMMAND_LOG:
        assert entry["evidence_id"] in appendix
        assert entry["command"] in appendix
        assert entry["why"] in appendix
    assert "refused before it ran" in appendix, "a rejection is evidence too"
    assert "PERMISSION_DENIED" in appendix, "why a read failed is the point of listing it"
    assert "2025-09-03" in appendix, "when it ran"


def test_the_rendered_document_is_structurally_valid(payload, index):
    content = _render(payload, index, reconciliation=_reconciliation(),
                      live_context=_live_context())
    assert validate_markdown(content) == []


def test_a_pipe_in_a_statement_cannot_split_a_table_row(payload, index):
    reconciliation = _reconciliation()
    reconciliation["sql_public"]["statement"] = "The state is STOPPED | not RUNNABLE."
    content = _render(payload, index, reconciliation=reconciliation,
                      live_context=_live_context())
    assert validate_markdown(content) == []


# ── the PDF, from the same objects ───────────────────────────────────────────


def test_the_pdf_carries_the_same_three_additions(payload, index):
    art = _artifacts(index)
    html = render_pdf_html(
        project_id="synthetic-project-id",
        scan_id=7,
        payload=payload,
        narratives={p: e["narrative"] for p, e in art["pillar_analysis"].items()},
        explanations={c: e["explanation"] for c, e in art["check_analysis"].items()},
        executive_summary=art["executive_summary"],
        analysis={
            "themes": art["themes"],
            "remediation_plan": art["remediation_plan"],
            "pillar_analysis": {p: e["analysis"] for p, e in art["pillar_analysis"].items()},
            "check_context": {c: e["why_here"] for c, e in art["check_analysis"].items()},
            "reconciliation": _reconciliation(),
        },
        live_context=_live_context(),
    )
    assert "<h2>Live-State Reconciliation</h2>" in html
    assert "<h2>Evidence Appendix</h2>" in html
    # The same labels the Markdown uses, from the same mapping.
    assert "No longer applicable" in html
    assert "Raised by live state" in html
    assert "Not checked against live state" in html
    assert "gcloud sql instances list --format=json" in html
    assert "refused before it ran" in html


# ── the node ─────────────────────────────────────────────────────────────────


def test_reconcile_does_not_call_a_model_when_there_is_nothing_to_reconcile(
    index, monkeypatch
):
    """An `unavailable` run has an empty log, so every verdict must be
    `no_evidence` — and the only thing a model call could add is the chance of
    inventing a citation."""
    def _explode(**kwargs):
        raise AssertionError("reconcile must not call the model with no evidence")

    monkeypatch.setattr(nodes, "generate_json", _explode)
    out = nodes.reconcile(
        {"ledger_index": index, "project_id": "p", "command_log": [], "report_id": 1}
    )
    assert set(out["reconciliation"]) == set(index)
    assert all(e["verdict"] == "no_evidence" for e in out["reconciliation"].values())


def test_reconcile_returns_a_verdict_for_every_check(index, monkeypatch):
    monkeypatch.setattr(
        nodes,
        "generate_json",
        lambda **kwargs: {
            "verdicts": [
                {"check_id": "sql_public", "verdict": "moot",
                 "statement": "Stopped.", "evidence": ["E1"]}
            ]
        },
    )
    monkeypatch.setattr(nodes, "_settings", lambda: object())
    out = nodes.reconcile(
        {
            "ledger_index": index,
            "project_id": "p",
            "report_id": 1,
            "command_log": COMMAND_LOG,
            "live_snapshot": {},
        }
    )
    assert out["reconciliation"]["sql_public"]["verdict"] == "moot"
    assert out["reconciliation"]["logging_disabled"]["verdict"] == "no_evidence"


def test_evidence_ids_come_from_the_run_and_nowhere_else():
    assert nodes.evidence_ids_of({"command_log": COMMAND_LOG}) == EVIDENCE_IDS
    assert nodes.evidence_ids_of({}) == set()


# ── routing ──────────────────────────────────────────────────────────────────


def test_a_c7_failure_sends_the_repair_pass_back_to_reconcile():
    from app.agents.report_graph import _after_repair

    assert _after_repair({"repair_targets": ["reconciliation"], "compose_queue": []}) == (
        "reconcile"
    )


def test_a_repaired_reconciliation_goes_straight_back_to_verify():
    """Not through `plan_remediation`. Nothing the plan is built from changed,
    so re-running it would spend a model call to produce the same waves."""
    from app.agents.report_graph import build_graph

    graph = build_graph()
    edges = graph.get_graph().edges
    targets = {e.target for e in edges if e.source == "reconcile"}
    assert targets == {"plan_remediation", "verify"}
