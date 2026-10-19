"""The deterministic half of report generation — everything Gemini is not
responsible for. No network, no credential; a seeded database and pure
functions.
"""

import datetime

import pytest

from app.models.department import Department
from app.models.finding import Finding, FindingStatus, MuteReason, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.waf_pillar_mapping import DEFAULT_PILLAR_MAPPING, SECURITY_PILLAR, WafPillarMapping
from app.services.reports import (
    NoReportableFindingsError,
    NoScanToReportOnError,
    build_report_payload,
    finalize_report,
    pillar_for,
    submit_report,
)


def _seed_mapping(db_session):
    for category, pillar in DEFAULT_PILLAR_MAPPING.items():
        db_session.merge(WafPillarMapping(category=category, pillar=pillar))
    db_session.flush()
    return dict(DEFAULT_PILLAR_MAPPING)


def _make_project(db_session, project_id="proj-1", freshservice_id="900"):
    dept = Department(freshservice_id=freshservice_id, name="Dept", domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    org = GcpOrganization(org_id=f"org-{project_id}", name="Org", department_id=dept.id)
    db_session.add(org)
    db_session.flush()
    project = Project(
        project_id=project_id, gcp_organization_id=org.id,
        target_sa_email=f"scanner@{project_id}.iam.gserviceaccount.com", deleted=False,
    )
    db_session.add(project)
    db_session.flush()
    return project


def _make_scan(db_session, project, *, status=ScanStatus.succeeded):
    user = User(email=f"actor-{project.id}@example.test", name="Actor")
    db_session.add(user)
    db_session.flush()
    scan = Scan(project_id=project.id, status=status, triggered_by_user_id=user.id)
    db_session.add(scan)
    db_session.flush()
    return scan, user


def _add_finding(
    db_session, project, scan, *, check_id="c1", resource_uid="r1", categories="encryption",
    status=FindingStatus.FAIL, severity=Severity.high, description="what it checks",
    muted=False, mute_reason=None,
):
    finding = Finding(
        project_id=project.id, check_id=check_id, resource_uid=resource_uid,
        finding_uid=f"uid-{resource_uid}", check_title=f"Title {check_id}",
        severity=severity, status=status, status_extended="detail here", region="global",
        service_name="svc", resource_type="type", resource_name=resource_uid,
        last_scan_id=scan.id, muted=muted, mute_reason=mute_reason,
        description=description, risk="why it matters",
        remediation_text="do the thing", remediation_cli="gcloud do-the-thing",
        categories=categories,
    )
    db_session.add(finding)
    db_session.flush()
    return finding


# ── pillar_for ───────────────────────────────────────────────────────────────


def test_first_listed_tag_wins():
    mapping = dict(DEFAULT_PILLAR_MAPPING)
    # Prowler pipe-separates; the rule reads the first tag only.
    assert pillar_for("logging | forensics-ready", mapping) == ("Operational Excellence", False)
    assert pillar_for("secrets | identity-access", mapping) == (SECURITY_PILLAR, False)


def test_empty_category_falls_back_to_security_and_is_not_flagged_unknown():
    """5.6% of the reference scan carries no category. These must land
    somewhere rather than vanishing from a customer-facing report — and an
    absent category is the documented fallback, not drift, so it is not
    counted as unknown."""
    assert pillar_for("", dict(DEFAULT_PILLAR_MAPPING)) == (SECURITY_PILLAR, False)
    assert pillar_for(None, dict(DEFAULT_PILLAR_MAPPING)) == (SECURITY_PILLAR, False)


def test_unknown_tag_falls_back_to_security_and_is_flagged():
    """A category Prowler adds in a future version must not break generation —
    but it must be visible, which is what the flag drives."""
    pillar, unknown = pillar_for("quantum-entanglement", dict(DEFAULT_PILLAR_MAPPING))
    assert pillar == SECURITY_PILLAR
    assert unknown is True


# ── build_report_payload ─────────────────────────────────────────────────────


def test_only_fail_and_manual_are_reported(db_session):
    _seed_mapping(db_session)
    project = _make_project(db_session)
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, check_id="fail-check", resource_uid="r1",
                 status=FindingStatus.FAIL)
    _add_finding(db_session, project, scan, check_id="manual-check", resource_uid="r2",
                 status=FindingStatus.MANUAL)
    _add_finding(db_session, project, scan, check_id="pass-check", resource_uid="r3",
                 status=FindingStatus.PASS)
    _add_finding(db_session, project, scan, check_id="gone-check", resource_uid="r4",
                 status=FindingStatus.RESOURCE_DOES_NOT_EXIST)

    payload = build_report_payload(db_session, project_id=project.id)
    checks = {g["check_id"] for groups in payload["pillars"].values() for g in groups}
    assert checks == {"fail-check", "manual-check"}


def test_findings_group_by_check_not_resource(db_session):
    """A check failing on forty buckets is one section with forty rows, not
    forty sections — this is what keeps a fifty-check report readable."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-group", freshservice_id="901")
    scan, _ = _make_scan(db_session, project)
    for i in range(3):
        _add_finding(db_session, project, scan, check_id="same-check", resource_uid=f"r{i}")

    payload = build_report_payload(db_session, project_id=project.id)
    groups = payload["pillars"][SECURITY_PILLAR]
    assert len(groups) == 1
    assert len(groups[0]["resources"]) == 3


def test_findings_without_description_are_skipped_and_counted(db_session):
    """Rows imported before remediation-detail capture have nothing to explain
    and no remediation to print. They are excluded from the body, but the count
    is carried so the report can say so rather than silently disagreeing with
    the findings screen."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-skip", freshservice_id="902")
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, check_id="ok", resource_uid="r1")
    _add_finding(db_session, project, scan, check_id="old", resource_uid="r2", description=None)

    payload = build_report_payload(db_session, project_id=project.id)
    assert payload["skipped_finding_count"] == 1
    checks = {g["check_id"] for groups in payload["pillars"].values() for g in groups}
    assert checks == {"ok"}


def test_empty_pillars_are_omitted_entirely(db_session):
    """No filler, no 'not applicable'. Prowler is a security scanner, so Cost,
    Performance and Sustainability are reliably empty."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-empty", freshservice_id="903")
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, categories="encryption")

    payload = build_report_payload(db_session, project_id=project.id)
    assert list(payload["pillars"]) == [SECURITY_PILLAR]


def test_groups_are_ordered_most_severe_first(db_session):
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-order", freshservice_id="904")
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, check_id="low-one", resource_uid="r1",
                 severity=Severity.low)
    _add_finding(db_session, project, scan, check_id="crit-one", resource_uid="r2",
                 severity=Severity.critical)

    payload = build_report_payload(db_session, project_id=project.id)
    assert [g["check_id"] for g in payload["pillars"][SECURITY_PILLAR]] == ["crit-one", "low-one"]


def test_muted_findings_are_excluded_by_default_and_counted(db_session):
    """A mute is a recorded decision not to remediate, so it is out of scope for
    a remediation report unless asked for. Including a large muted set by
    default can bury actionable findings in noise.

    The count is returned so the document can state the omission rather than
    silently presenting a tenth of the picture."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-mute", freshservice_id="905")
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, check_id="open", resource_uid="r1")
    _add_finding(db_session, project, scan, check_id="accepted", resource_uid="r2",
                 muted=True, mute_reason=MuteReason.risk_accepted)

    payload = build_report_payload(db_session, project_id=project.id)

    checks = {g["check_id"] for groups in payload["pillars"].values() for g in groups}
    assert checks == {"open"}
    assert payload["muted_excluded_count"] == 1


def test_muted_findings_are_included_on_request_and_carry_their_reason(db_session):
    """When asked for, they appear inline and tagged rather than hidden in an
    appendix: the reader is an L1 or a customer who will not know to look for
    one, and an accepted risk they cannot see reads as an omission when they
    later find it."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-mute-in", freshservice_id="915")
    scan, _ = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, muted=True, mute_reason=MuteReason.risk_accepted)

    payload = build_report_payload(db_session, project_id=project.id, include_muted=True)

    resource = payload["pillars"][SECURITY_PILLAR][0]["resources"][0]
    assert resource["muted"] is True
    assert resource["mute_reason"] == "risk_accepted"
    assert payload["muted_excluded_count"] == 0


def test_submit_refuses_when_everything_is_muted_and_says_why(db_session):
    """The guard has to use the same scope the report will, or a fully-muted
    project submits happily and produces an empty document. The message must
    also point at the right fix — telling someone to re-scan when the real
    problem is that they muted everything sends them somewhere useless."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-all-muted", freshservice_id="916")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, muted=True, mute_reason=MuteReason.risk_accepted)

    with pytest.raises(NoReportableFindingsError) as excinfo:
        submit_report(db_session, project_id=project.id, actor_user_id=user.id)
    assert excinfo.value.all_muted is True
    assert "include muted" in str(excinfo.value)

    # ...and succeeds once they are in scope.
    report = submit_report(
        db_session, project_id=project.id, actor_user_id=user.id, include_muted=True
    )
    assert report.include_muted is True


# ── submit guards ────────────────────────────────────────────────────────────


def test_refuses_when_the_project_has_no_succeeded_scan(db_session):
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-noscan", freshservice_id="906")
    scan, user = _make_scan(db_session, project, status=ScanStatus.failed)

    with pytest.raises(NoScanToReportOnError):
        submit_report(db_session, project_id=project.id, actor_user_id=user.id)


def test_refuses_when_no_finding_carries_remediation_detail(db_session):
    """The day-one state for any scan imported before this feature: caught at
    submit so the user gets an actionable answer instead of a failed row."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-nodetail", freshservice_id="907")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, description=None)

    with pytest.raises(NoReportableFindingsError):
        submit_report(db_session, project_id=project.id, actor_user_id=user.id)


def test_refuses_when_the_only_finding_has_a_whitespace_only_description(db_session):
    """`build_report_payload` treats a whitespace-only description as empty
    via `.strip()`. The submit-time guard has to agree — a plain `!= ""` SQL
    check previously let this finding count as reportable at submit time,
    passing the guard and then producing an empty document with no error at
    all, since the payload build would still skip it."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-blank-desc", freshservice_id="917")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, description="   ")

    with pytest.raises(NoReportableFindingsError):
        submit_report(db_session, project_id=project.id, actor_user_id=user.id)


def test_submit_records_the_resolved_scan_and_an_audit_entry(db_session):
    from app.models.audit_log import AuditLog

    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-ok", freshservice_id="908")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan)

    report = submit_report(db_session, project_id=project.id, actor_user_id=user.id)

    assert report.scan_id == scan.id
    assert report.status.value == "queued"
    assert report.task_reference_id.startswith("RPT-")
    entry = (
        db_session.query(AuditLog)
        .filter_by(target_type="report", target_id=str(report.id))
        .one()
    )
    assert entry.action_type == "report.request"


# ── PDF content persistence ───────────────────────────────────────────────────


def test_finalize_report_persists_pdf_content_and_has_pdf_reflects_it(db_session):
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-pdf", freshservice_id="920")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan)
    report = submit_report(db_session, project_id=project.id, actor_user_id=user.id)

    finalized = finalize_report(
        db_session,
        report_id=report.id,
        content="# Report",
        pdf_content=b"%PDF-1.7 fake bytes",
        skipped=0,
        unknown_categories=0,
    )

    assert finalized.pdf_content == b"%PDF-1.7 fake bytes"
    assert finalized.has_pdf is True


def test_report_with_no_pdf_content_reports_has_pdf_false(db_session):
    """A report row from before this column existed (or any row where
    `pdf_content` is genuinely NULL) must read as `has_pdf=False`, not error
    — this is what lets the API and frontend distinguish an old report from
    one that has a PDF to serve."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="proj-no-pdf", freshservice_id="921")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan)
    report = submit_report(db_session, project_id=project.id, actor_user_id=user.id)

    assert report.has_pdf is False
    assert report.pdf_content is None
