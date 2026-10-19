"""Unit tests for the Celery task's orchestration logic. The DB and Docker
boundaries (services/scans.py, integrations/prowler_runner.py, and now
services/importer.py) are exercised directly by their own test modules; here
everything is faked so the test never touches a real Postgres connection or
a real container — the task itself owns no logic beyond "call these in the
right order and always leave the scan in a terminal state.\""""

import pytest

from app.integrations.prowler_runner import ScanLaunchError, ScanRunResult
from app.models.scan import ScanStatus
from app.services.scans import ProjectMissingError
from app.worker import tasks


class _FakeImportingScan:
    """Stands in for `mark_importing`'s real return value — the task only
    reads `.status` off it to decide whether a concurrent cancel beat it
    there (see test_scans.py's cancelled-scan race tests for the real
    version of that check)."""

    status = ScanStatus.importing


class _FakeProject:
    def __init__(self):
        self.project_id = "proj-1"
        self.target_sa_email = "sa@proj-1.iam.gserviceaccount.com"


class _FakeScan:
    def __init__(self, project_id=1):
        self.id = 1
        self.project_id = project_id


class _FakeSession:
    def __init__(self, scan, project):
        self._objects = {}
        self.scan = scan
        self.project = project
        self.closed = False
        self.rolled_back = False

    def get(self, model, pk):
        from app.models.project import Project
        from app.models.scan import Scan

        if model is Scan:
            return self.scan
        if model is Project:
            return self.project
        return None

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _settings_stub(monkeypatch):
    values = {
        "REPORTS_PATH": "/reports",
        "HOST_REPORTS_PATH": "/abs/reports",
        "PROWLER_IMAGE": "toniblyx/prowler:5.39.0",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "GCLOUD_ADC_PATH": "",
        "SCAN_TIMEOUT_SECONDS": "7200",
    }
    monkeypatch.setattr(tasks, "get_settings", lambda: values)


def _wire_session(monkeypatch, session):
    monkeypatch.setattr(tasks, "get_session_factory", lambda: (lambda: session))


def test_success_path_marks_running_then_imports(monkeypatch):
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    calls = []
    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: (calls.append(("launch", kw)), "container-1")[1])
    monkeypatch.setattr(
        tasks, "wait_for_scan",
        lambda **kw: (calls.append(("wait", kw)), ScanRunResult(
            container_id="container-1", exit_code=0, timed_out=False, log_text="ok"
        ))[1],
    )
    monkeypatch.setattr(
        tasks, "mark_running",
        lambda db, *, scan_id, container_id, reports_path: calls.append(("mark_running", scan_id, container_id)),
    )
    imported = {}
    monkeypatch.setattr(
        tasks, "mark_importing",
        lambda db, *, scan_id, exit_code: (
            calls.append(("mark_importing", scan_id, exit_code)), _FakeImportingScan()
        )[1],
    )
    monkeypatch.setattr(
        tasks, "import_scan_results",
        lambda db, *, scan_id: imported.update(scan_id=scan_id),
    )

    tasks.run_scan_task(1)

    order = [c[0] for c in calls]
    assert order == ["launch", "mark_running", "wait", "mark_importing"]
    assert imported == {"scan_id": 1}
    assert session.closed is True


def test_exit_code_3_treated_as_success_not_failure(monkeypatch):
    """Prowler exits 3 when the scan ran fine but found FAIL checks — the
    normal case when findings are present, not an application-level failure. The
    task must hand off to the importer, not synthesize a failure."""
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(
        tasks, "wait_for_scan",
        lambda **kw: ScanRunResult(container_id="container-1", exit_code=3, timed_out=False, log_text="fails found"),
    )
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)
    imported = {}
    importing = {}
    monkeypatch.setattr(
        tasks, "mark_importing",
        lambda db, *, scan_id, exit_code: (
            importing.update(scan_id=scan_id, exit_code=exit_code), _FakeImportingScan()
        )[1],
    )
    monkeypatch.setattr(tasks, "import_scan_results", lambda db, *, scan_id: imported.update(scan_id=scan_id))
    failed = {}
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, **kw: failed.update(kw),
    )

    tasks.run_scan_task(1)

    assert importing == {"scan_id": 1, "exit_code": 3}
    assert imported == {"scan_id": 1}
    assert failed == {}


def test_launch_failure_finalizes_as_failed_without_waiting(monkeypatch):
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    def _raise_launch(**kw):
        raise ScanLaunchError("no such host: docker daemon unreachable")

    monkeypatch.setattr(tasks, "launch_scan", _raise_launch)
    waited = []
    monkeypatch.setattr(tasks, "wait_for_scan", lambda **kw: waited.append(kw))
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)
    finalized = {}
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, *, scan_id, exit_code, timed_out, error_message: finalized.update(
            scan_id=scan_id, exit_code=exit_code, timed_out=timed_out, error_message=error_message
        ),
    )

    tasks.run_scan_task(1)

    assert waited == []
    assert finalized["exit_code"] is None
    assert finalized["timed_out"] is False
    assert "docker daemon unreachable" in finalized["error_message"]
    assert session.closed is True


def test_timeout_path_finalizes_with_timed_out_true(monkeypatch):
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(
        tasks, "wait_for_scan",
        lambda **kw: ScanRunResult(container_id="container-1", exit_code=None, timed_out=True, log_text="stuck"),
    )
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)
    finalized = {}
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, *, scan_id, exit_code, timed_out, error_message: finalized.update(
            scan_id=scan_id, exit_code=exit_code, timed_out=timed_out, error_message=error_message
        ),
    )

    tasks.run_scan_task(1)

    assert finalized["timed_out"] is True
    assert "time ceiling" in finalized["error_message"]


def test_nonzero_non_prowler_exit_code_finalizes_as_failed(monkeypatch):
    """An exit code outside Prowler's own success set (0, 3) — e.g. a crash
    or bad credentials — never reaches the importer."""
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(
        tasks, "wait_for_scan",
        lambda **kw: ScanRunResult(container_id="container-1", exit_code=1, timed_out=False, log_text="boom"),
    )
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)
    imported = []
    monkeypatch.setattr(tasks, "import_scan_results", lambda db, *, scan_id: imported.append(scan_id))
    finalized = {}
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, *, scan_id, exit_code, timed_out, error_message: finalized.update(
            scan_id=scan_id, exit_code=exit_code, timed_out=timed_out, error_message=error_message
        ),
    )

    tasks.run_scan_task(1)

    assert imported == []
    assert finalized["exit_code"] == 1
    assert finalized["timed_out"] is False


def test_cancelled_mid_flight_skips_import(monkeypatch):
    """An operator cancelled this scan while the container was mid-run.
    `mark_importing` refuses to overwrite that (see test_scans.py) and hands
    back the still-cancelled row — the task must notice and never call the
    importer for a scan nobody wants imported."""
    scan = _FakeScan()
    session = _FakeSession(scan, _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(
        tasks, "wait_for_scan",
        lambda **kw: ScanRunResult(container_id="container-1", exit_code=0, timed_out=False, log_text="ok"),
    )
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)

    class _StillCancelledScan:
        status = ScanStatus.cancelled

    monkeypatch.setattr(tasks, "mark_importing", lambda db, *, scan_id, exit_code: _StillCancelledScan())
    imported = []
    monkeypatch.setattr(tasks, "import_scan_results", lambda db, *, scan_id: imported.append(scan_id))

    tasks.run_scan_task(1)

    assert imported == []
    assert session.closed is True


# ── the "always terminal" invariant ──────────────────────────────────────
# The task's docstring promises every exit path leaves the scan row in a
# terminal state. Before these tests only ScanLaunchError kept that promise;
# any other exception left the row `queued`/`running` with nothing able to
# reach it again (max_retries=0, no on_failure hook, and the timeout sweep
# only looks at rows a container is actually attached to).


def _finalize_recorder(monkeypatch):
    finalized = {}
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, *, scan_id, exit_code, timed_out, error_message: finalized.update(
            scan_id=scan_id, exit_code=exit_code, timed_out=timed_out, error_message=error_message
        ),
    )
    return finalized


def test_unexpected_error_still_finalizes_the_scan(monkeypatch):
    """An error from a path with no handler of its own — here an OSError out
    of wait_for_scan, standing in for the full-disk case — must still land the
    row in a terminal state, and must still reach the worker log."""
    session = _FakeSession(_FakeScan(), _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)

    def _boom(**kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tasks, "wait_for_scan", _boom)
    finalized = _finalize_recorder(monkeypatch)

    with pytest.raises(OSError):
        tasks.run_scan_task(1)

    assert finalized["scan_id"] == 1
    assert finalized["exit_code"] is None
    assert finalized["timed_out"] is False
    assert "No space left on device" in finalized["error_message"]
    assert session.closed is True


def test_unexpected_error_rolls_back_before_finalizing(monkeypatch):
    """finalize_scan_failure commits. A failure mid-flush would make that
    commit raise as well, so the rollback has to come first or the rescue
    silently does nothing."""
    session = _FakeSession(_FakeScan(), _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: "container-1")
    monkeypatch.setattr(tasks, "mark_running", lambda db, **kw: None)
    monkeypatch.setattr(tasks, "wait_for_scan", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))

    order = []
    monkeypatch.setattr(
        tasks, "finalize_scan_failure",
        lambda db, **kw: order.append(("finalize", db.rolled_back)),
    )

    with pytest.raises(RuntimeError):
        tasks.run_scan_task(1)

    assert session.rolled_back is True
    assert order == [("finalize", True)]


def test_missing_project_is_named_not_an_attribute_error(monkeypatch):
    """A scan pointing at a project row that is gone. Projects are soft
    deleted so this should be unreachable, but if it happens the row must say
    so rather than dying on an attribute of None."""
    session = _FakeSession(_FakeScan(project_id=42), project=None)
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    launched = []
    monkeypatch.setattr(tasks, "launch_scan", lambda **kw: launched.append(kw))
    finalized = _finalize_recorder(monkeypatch)

    with pytest.raises(ProjectMissingError):
        tasks.run_scan_task(1)

    assert launched == []
    assert "42" in finalized["error_message"]
    assert session.closed is True


# ── report generation ────────────────────────────────────────────────────────
# Same invariant as run_scan_task: no exit path leaves the row non-terminal.
# The extra rule here is all-or-nothing — a report that failed halfway must
# store no content, because a truncated customer-facing document is worse than
# a clear failure to retry.


def test_report_failure_stores_no_partial_content(monkeypatch):
    session = _FakeSession(_FakeScan(), _FakeProject())
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)

    monkeypatch.setattr(tasks.reports_service, "get_report", lambda db, *, report_id, visible_department_ids: _FakeReport())
    monkeypatch.setattr(tasks.reports_service, "mark_generating", lambda db, **kw: None)
    monkeypatch.setattr(
        tasks.reports_service, "build_report_payload",
        lambda db, *, project_id, include_muted: {
            "pillars": {"Reliability": [{"check_id": "c1"}]},
            "severity_counts": {"Reliability": {"high": 1}},
            "skipped_finding_count": 0,
            "unknown_category_count": 0,
            "muted_excluded_count": 0,
        },
    )
    monkeypatch.setattr(
        tasks.report_render, "pillar_user_content", lambda pillar, groups: "payload"
    )

    def _boom(**kwargs):
        raise RuntimeError("Vertex AI returned 503")

    monkeypatch.setattr(tasks, "generate_json", _boom)

    failed = {}
    monkeypatch.setattr(
        tasks.reports_service, "fail_report",
        lambda db, *, report_id, error_message: failed.update(
            report_id=report_id, error_message=error_message
        ),
    )
    finalized = []
    monkeypatch.setattr(tasks.reports_service, "finalize_report", lambda db, **kw: finalized.append(kw))

    with pytest.raises(RuntimeError):
        tasks.generate_report_task(1)

    assert failed["report_id"] == 1
    assert "503" in failed["error_message"]
    assert finalized == []          # nothing written
    assert session.rolled_back is True
    assert session.closed is True


class _FakeReport:
    id = 1
    project_id = 1
    scan_id = 12
    include_muted = False


def _full_payload():
    """A payload shaped enough to survive a real `render_markdown()` +
    `validate_markdown()` pass — the success-path test below exercises those
    for real (pure, cheap) and only mocks the externally-costly calls
    (Gemini, WeasyPrint)."""
    return {
        "pillars": {
            "Reliability": [
                {
                    "check_id": "c1",
                    "check_title": "Some check",
                    "severity": "high",
                    "categories": "encryption",
                    "description": "desc",
                    "risk": "risk",
                    "remediation_text": "do the thing",
                    "remediation_cli": "gcloud do-thing",
                    "remediation_terraform": None,
                    "resources": [
                        {"resource_name": "r1", "region": "us", "status_extended": "bad",
                         "muted": False, "mute_reason": None},
                    ],
                }
            ]
        },
        "severity_counts": {"Reliability": {"high": 1}},
        "skipped_finding_count": 0,
        "unknown_category_count": 0,
        "muted_excluded_count": 0,
    }


def _generate_json_stub(**kwargs):
    """Shared fake for the three distinct `generate_json` calls the task
    makes (per-pillar narrative, executive summary, advisory review) — routed
    by a substring of the system prompt, the only thing that varies."""
    instruction = kwargs["system_instruction"]
    if "executive summary" in instruction:
        return {"executive_summary": "Overall summary."}
    if "proofreading the Markdown" in instruction:
        return {"issues": []}
    return {
        "pillar_narrative": "Pillar narrative text.",
        "findings": [{"check_id": "c1", "explanation": "Explanation text."}],
    }


def _wire_report_success_stubs(monkeypatch, session):
    _settings_stub(monkeypatch)
    _wire_session(monkeypatch, session)
    monkeypatch.setattr(tasks.reports_service, "get_report", lambda db, *, report_id, visible_department_ids: _FakeReport())
    monkeypatch.setattr(tasks.reports_service, "mark_generating", lambda db, **kw: None)
    monkeypatch.setattr(
        tasks.reports_service, "build_report_payload",
        lambda db, *, project_id, include_muted: _full_payload(),
    )
    monkeypatch.setattr(tasks, "generate_json", lambda **kw: _generate_json_stub(**kw))


def test_report_success_path_persists_markdown_and_pdf_together(monkeypatch):
    """The PDF is rendered from the exact same in-memory payload/narratives
    used for the Markdown, and both land in the same `finalize_report` call —
    no path stores one artifact without the other."""
    session = _FakeSession(_FakeScan(), _FakeProject())
    _wire_report_success_stubs(monkeypatch, session)

    monkeypatch.setattr(
        tasks.report_pdf, "render_pdf_bytes", lambda **kw: b"%PDF-fake-bytes"
    )
    finalized = []
    monkeypatch.setattr(tasks.reports_service, "finalize_report", lambda db, **kw: finalized.append(kw))

    tasks.generate_report_task(1)

    assert len(finalized) == 1
    assert finalized[0]["pdf_content"] == b"%PDF-fake-bytes"
    assert "Overall summary." in finalized[0]["content"]
    assert session.closed is True


def test_pdf_render_failure_fails_the_whole_report(monkeypatch):
    """A WeasyPrint failure is fatal, matching the all-or-nothing rule
    `MarkdownValidationError` already enforces — a report with Markdown but
    no PDF is a half-written customer-facing artifact. `finalize_report`
    must never be called on this path."""
    session = _FakeSession(_FakeScan(), _FakeProject())
    _wire_report_success_stubs(monkeypatch, session)

    def _boom(**kwargs):
        raise RuntimeError("weasyprint: font backend unavailable")

    monkeypatch.setattr(tasks.report_pdf, "render_pdf_bytes", _boom)
    failed = {}
    monkeypatch.setattr(
        tasks.reports_service, "fail_report",
        lambda db, *, report_id, error_message: failed.update(
            report_id=report_id, error_message=error_message
        ),
    )
    finalized = []
    monkeypatch.setattr(tasks.reports_service, "finalize_report", lambda db, **kw: finalized.append(kw))

    with pytest.raises(tasks.PdfRenderError):
        tasks.generate_report_task(1)

    assert failed["report_id"] == 1
    assert "font backend unavailable" in failed["error_message"]
    assert finalized == []
    assert session.rolled_back is True
    assert session.closed is True


# ── run-level scores ─────────────────────────────────────────────────────────


class _RecordingSpan:
    """Stands in for the run's root span, capturing what was scored on it."""

    def __init__(self):
        self.scores = []

    def score_trace(self, **kwargs):
        self.scores.append(kwargs)
        return self


def _scores_for(final):
    span = _RecordingSpan()
    tasks._record_run_scores(span, final)
    return {s["name"]: s for s in span.scores}


def test_a_clean_run_scores_a_full_gate_pass_rate():
    scores = _scores_for(
        {
            "verification": {
                "gates_run": ["C1", "C2", "C3", "C6", "C4", "C5", "markdown"],
                "failures": [],
                "document_problems": [],
            },
            "revision_count": 0,
            "critique": {"verdict": "accept", "assessment": "reads well"},
        }
    )
    assert scores["gate_pass_rate"]["value"] == 1.0
    assert scores["revisions"]["value"] == 0.0
    assert scores["critique_verdict"]["value"] == "accept"
    assert scores["critique_verdict"]["data_type"] == "CATEGORICAL"


def test_a_failed_gate_lowers_the_rate_and_is_named_in_the_comment():
    scores = _scores_for(
        {
            "verification": {
                "gates_run": ["C1", "C2", "C3", "C6"],
                "failures": [{"gate": "C3", "detail": "two checks uncovered"}],
                "document_problems": [],
            },
            "revision_count": 2,
            "critique": {"verdict": "revise", "assessment": "thin"},
        }
    )
    assert scores["gate_pass_rate"]["value"] == 0.75
    assert "failed: C3" in scores["gate_pass_rate"]["comment"]
    assert scores["revisions"]["value"] == 2.0


def test_a_markdown_problem_with_no_gate_prefix_is_charged_to_markdown():
    """`verify_rendered` folds `validate_markdown`'s unprefixed strings in
    beside C4/C5, so an unattributable problem must still cost something."""
    scores = _scores_for(
        {
            "verification": {
                "gates_run": ["C4", "C5", "markdown"],
                "failures": [],
                "document_problems": ["unclosed code fence at line 12"],
            },
            "revision_count": 0,
            "critique": {},
        }
    )
    assert scores["gate_pass_rate"]["value"] == 2 / 3
    assert "failed: markdown" in scores["gate_pass_rate"]["comment"]
    assert "critique_verdict" not in scores


def test_a_run_with_no_verification_still_records_its_revisions():
    """A run that died before any gate ran has no rate to report, and scoring a
    zero there would read as "every gate failed" rather than "none ran"."""
    scores = _scores_for({"revision_count": 1})
    assert "gate_pass_rate" not in scores
    assert scores["revisions"]["value"] == 1.0


# ── the suite must not export its own spans ──────────────────────────────────


def test_tracing_is_disabled_by_the_time_an_ordinary_test_runs():
    """The regression guard for a test-isolation failure mode.

    `conftest._no_tracing_in_tests` must be function-scoped. This file's own
    `_clean_client` calls `reset_for_tests()` after every test, which clears the
    resolved flag; a later test must still keep tracing disabled.

    Placed in an *ordinary* test file deliberately, and not in
    `test_observability.py`: that file's own fixture resolves a client per test
    by design, so the invariant is meaningless there. What matters is that a
    file running after it still sees tracing off. It asserts the module globals
    rather than calling `client()`, because calling it would itself resolve
    one.
    """
    import app.observability as module

    assert module._resolved is True
    assert module._client is None
