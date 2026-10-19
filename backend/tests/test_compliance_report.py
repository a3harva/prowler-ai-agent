"""The compliance report: a live join of a project's findings against the
loaded rulebook, rolled up to requirement level. No fixtures on disk here
— unlike test_compliance.py, this doesn't seed through
`seed_rulebook_from_scan`; it writes `ComplianceRequirement` rows directly,
since the rollup logic under test only cares about what's in the table,
not how it got there.
"""

import csv

from app.models.compliance_requirement import ComplianceRequirement
from app.models.department import Department
from app.models.finding import Finding, FindingStatus, MuteReason, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.compliance import compliance_report, list_frameworks, seed_rulebook_from_scan
from app.services.importer import import_scan_results

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


def _make_project(db_session, project_id="proj-1") -> tuple[Project, Department]:
    dept = Department(freshservice_id=project_id, name=f"Dept {project_id}", domains=[], deleted=False)
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
    return project, dept


def _make_scan(db_session, project) -> Scan:
    actor_id = _make_actor(db_session, email=f"scan-actor-{project.project_id}@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.succeeded,
        triggered_by_user_id=actor_id, reports_path="/reports/irrelevant",
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _add_requirement(db_session, *, framework="CIS-2.0", framework_name="CIS 2.0", requirement_id, check_id, description=None):
    db_session.add(
        ComplianceRequirement(
            framework=framework, framework_name=framework_name, requirement_id=requirement_id,
            requirement_description=description, check_id=check_id, attributes={},
            prowler_version="5.39.0",
        )
    )
    db_session.flush()


def _add_finding(
    db_session, project, scan, *, check_id, resource_uid, status=FindingStatus.PASS,
    muted=False, mute_reason=None,
):
    finding = Finding(
        project_id=project.id, check_id=check_id, resource_uid=resource_uid,
        finding_uid=f"finding-{check_id}-{resource_uid}", check_title=f"Check {check_id}",
        severity=Severity.high, status=status, region="us-central1",
        muted=muted, mute_reason=mute_reason,
        service_name="compute", resource_type="compute.googleapis.com/Instance",
        resource_name=resource_uid, last_scan_id=scan.id,
    )
    db_session.add(finding)
    db_session.flush()
    return finding


_SCAN_COLUMNS = [
    "AUTH_METHOD", "TIMESTAMP", "ACCOUNT_UID", "ACCOUNT_NAME", "ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID", "ACCOUNT_ORGANIZATION_NAME", "ACCOUNT_TAGS",
    "FINDING_UID", "PROVIDER", "CHECK_ID", "CHECK_TITLE", "CHECK_TYPE", "STATUS",
    "STATUS_EXTENDED", "MUTED", "SERVICE_NAME", "SUBSERVICE_NAME", "SEVERITY",
    "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME", "RESOURCE_DETAILS",
    "RESOURCE_TAGS", "PARTITION", "REGION", "DESCRIPTION", "RISK", "RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT", "REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC", "REMEDIATION_CODE_TERRAFORM", "REMEDIATION_CODE_CLI",
    "REMEDIATION_CODE_OTHER", "COMPLIANCE", "CATEGORIES", "DEPENDS_ON", "RELATED_TO",
    "NOTES", "PROWLER_VERSION", "ADDITIONAL_URLS", "ACCOUNT_OU_UID", "ACCOUNT_OU_NAME",
]

_COMPLIANCE_COLUMNS = [
    "PROVIDER", "DESCRIPTION", "PROJECTID", "LOCATION", "ASSESSMENTDATE",
    "REQUIREMENTS_ID", "REQUIREMENTS_DESCRIPTION", "REQUIREMENTS_ATTRIBUTES_SECTION",
    "STATUS", "STATUSEXTENDED", "RESOURCEID", "RESOURCENAME", "CHECKID", "MUTED",
    "FRAMEWORK", "NAME",
]


def _write_synthetic_scan_and_rulebook(reports_dir) -> None:
    scan_row = {column: "" for column in _SCAN_COLUMNS}
    scan_row.update(
        {
            "PROVIDER": "gcp",
            "FINDING_UID": "demo-network-finding",
            "CHECK_ID": "cloudfunction_function_inside_vpc",
            "CHECK_TITLE": "Function is connected to a VPC network",
            "STATUS": "FAIL",
            "STATUS_EXTENDED": "Demo function has no VPC connector.",
            "MUTED": "False",
            "SERVICE_NAME": "cloudfunction",
            "SEVERITY": "medium",
            "RESOURCE_TYPE": "cloudfunctions.googleapis.com/Function",
            "RESOURCE_UID": "projects/synthetic-project-id/functions/sample-function",
            "RESOURCE_NAME": "demo-function",
            "REGION": "us-central1",
            "PROWLER_VERSION": "5.39.0",
        }
    )
    with open(reports_dir / "scan.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_SCAN_COLUMNS, delimiter=";")
        writer.writeheader()
        writer.writerow(scan_row)

    compliance_row = {column: "" for column in _COMPLIANCE_COLUMNS}
    compliance_row.update(
        {
            "PROVIDER": "gcp",
            "REQUIREMENTS_ID": "12.2",
            "REQUIREMENTS_DESCRIPTION": "Validate network isolation.",
            "CHECKID": "cloudfunction_function_inside_vpc",
            "MUTED": "False",
            "FRAMEWORK": "CIS-Controls",
            "NAME": "CIS Controls v8.1",
        }
    )
    with open(reports_dir / "compliance" / "synthetic_cis_controls.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_COMPLIANCE_COLUMNS, delimiter=";")
        writer.writeheader()
        writer.writerow(compliance_row)


# ── rollup ───────────────────────────────────────────────────────────────


def test_requirement_passes_when_every_mapped_check_passes(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r2", status=FindingStatus.PASS)

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["summary"] == {
        "passed": 1, "failed": 0, "needs_review": 0, "not_assessed": 0,
        "total_requirements": 1, "score_percent": 100,
    }
    assert report["requirements"][0]["status"] == "pass"


def test_requirement_fails_if_any_resource_behind_a_mapped_check_fails(db_session):
    """Worst-case rollup: one FAILing resource among many PASSing ones for
    the same check still fails the check, and the requirement with it."""
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r2", status=FindingStatus.FAIL)

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["requirements"][0]["status"] == "fail"
    assert report["summary"]["failed"] == 1
    assert report["summary"]["score_percent"] == 0


def test_requirement_fails_when_any_mapped_check_fails_even_if_others_pass(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_requirement(db_session, requirement_id="req-1", check_id="check_b")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)
    _add_finding(db_session, project, scan, check_id="check_b", resource_uid="r1", status=FindingStatus.FAIL)

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["requirements"][0]["status"] == "fail"


def test_requirement_with_no_finding_is_not_assessed_and_excluded_from_score(db_session):
    project, _dept = _make_project(db_session)
    _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["requirements"][0]["status"] == "not_assessed"
    assert report["summary"]["not_assessed"] == 1
    assert report["summary"]["score_percent"] is None  # nothing to score — never a misleading 100%


def test_requirement_needs_review_when_manual_and_no_failures(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.MANUAL)

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["requirements"][0]["status"] == "needs_review"
    assert report["summary"]["needs_review"] == 1
    # needs_review counts toward neither pass nor fail.
    assert report["summary"]["score_percent"] is None


def test_resource_does_not_exist_findings_are_ignored(db_session):
    """A gone resource can't attest current compliance — its finding must
    not keep a requirement looking PASSed (or anything else) forever."""
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(
        db_session, project, scan, check_id="check_a", resource_uid="r1",
        status=FindingStatus.RESOURCE_DOES_NOT_EXIST,
    )

    report = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report["requirements"][0]["status"] == "not_assessed"


def test_muted_findings_excluded_by_default_and_included_on_toggle(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(
        db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.FAIL,
        muted=True, mute_reason=MuteReason.risk_accepted,
    )

    excluded = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")
    assert excluded["requirements"][0]["status"] == "not_assessed"  # the only finding is muted, excluded by default

    included = compliance_report(
        db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0", include_muted=True
    )
    assert included["requirements"][0]["status"] == "fail"
    assert included["summary"]["score_percent"] == 0


def test_report_only_covers_the_requested_framework(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, framework="CIS-2.0", framework_name="CIS 2.0", requirement_id="req-1", check_id="check_a")
    _add_requirement(db_session, framework="CIS-3.0", framework_name="CIS 3.0", requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.FAIL)

    report_2_0 = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")
    report_3_0 = compliance_report(db_session, project_id=project.id, framework="CIS-3.0", framework_name="CIS 3.0")

    assert len(report_2_0["requirements"]) == 1
    assert len(report_3_0["requirements"]) == 1
    assert report_2_0["framework_name"] == "CIS 2.0"
    assert report_3_0["framework_name"] == "CIS 3.0"


def test_report_scoped_to_the_requested_project_only(db_session):
    project_a, _dept_a = _make_project(db_session, "proj-a")
    project_b, _dept_b = _make_project(db_session, "proj-b")
    scan_a = _make_scan(db_session, project_a)
    scan_b = _make_scan(db_session, project_b)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project_a, scan_a, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)
    _add_finding(db_session, project_b, scan_b, check_id="check_a", resource_uid="r1", status=FindingStatus.FAIL)

    report_a = compliance_report(db_session, project_id=project_a.id, framework="CIS-2.0", framework_name="CIS 2.0")
    report_b = compliance_report(db_session, project_id=project_b.id, framework="CIS-2.0", framework_name="CIS 2.0")

    assert report_a["requirements"][0]["status"] == "pass"
    assert report_b["requirements"][0]["status"] == "fail"


def test_report_reflects_findings_immediately_after_a_new_import(db_session):
    """Nothing about the report is precomputed — a finding written after
    the rulebook was loaded must show up on the very next call, with no
    refresh/recompute step."""
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")

    before = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")
    assert before["requirements"][0]["status"] == "not_assessed"

    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)

    after = compliance_report(db_session, project_id=project.id, framework="CIS-2.0", framework_name="CIS 2.0")
    assert after["requirements"][0]["status"] == "pass"


# ── frameworks list (ordering) ──────────────────────────────────────────


def test_list_frameworks_orders_by_live_check_match_count_in_the_project(db_session):
    project, _dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, framework="A", framework_name="Framework A", requirement_id="r1", check_id="check_a")
    _add_requirement(db_session, framework="B", framework_name="Framework B", requirement_id="r1", check_id="check_b")
    _add_requirement(db_session, framework="B", framework_name="Framework B", requirement_id="r2", check_id="check_c")
    # Framework B has two matching checks in this project; A has none.
    _add_finding(db_session, project, scan, check_id="check_b", resource_uid="r1", status=FindingStatus.PASS)
    _add_finding(db_session, project, scan, check_id="check_c", resource_uid="r1", status=FindingStatus.PASS)

    frameworks = list_frameworks(db_session, project_id=project.id)

    assert [f["framework"] for f in frameworks] == ["B", "A"]
    assert frameworks[0]["match_count"] == 2
    assert frameworks[1]["match_count"] == 0


def test_list_frameworks_keeps_versions_distinct(db_session):
    project, _dept = _make_project(db_session)
    _add_requirement(db_session, framework="CIS", framework_name="CIS v2.0.0", requirement_id="r1", check_id="check_a")
    _add_requirement(db_session, framework="CIS", framework_name="CIS v3.0.0", requirement_id="r1", check_id="check_a")

    frameworks = list_frameworks(db_session, project_id=project.id)

    names = {f["framework_name"] for f in frameworks}
    assert names == {"CIS v2.0.0", "CIS v3.0.0"}


# ── API layer / RBAC ────────────────────────────────────────────────────


def _as_admin(monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def test_viewer_can_view_the_report_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    scan = _make_scan(db_session, project)
    _add_requirement(db_session, requirement_id="req-1", check_id="check_a")
    _add_finding(db_session, project, scan, check_id="check_a", resource_uid="r1", status=FindingStatus.PASS)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get(
        f"/api/compliance/report?project_id={project.id}&framework=CIS-2.0&framework_name=CIS%202.0"
    )
    assert response.status_code == 200
    assert response.json()["summary"]["passed"] == 1


def test_viewer_cannot_report_on_a_project_outside_visible_departments(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project_a, _dept_a = _make_project(db_session, "proj-a")
    _project_b, dept_b = _make_project(db_session, "proj-b")
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_b.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get(
        f"/api/compliance/report?project_id={project_a.id}&framework=CIS-2.0&framework_name=CIS%202.0"
    )
    assert response.status_code == 404


def test_frameworks_endpoint_requires_sign_in(client):
    response = client.get("/api/compliance/frameworks?project_id=1")
    assert response.status_code == 401


# ── synthetic end-to-end import and rulebook coverage ────────────────────


def test_requirement_verdict_matches_synthetic_import_and_rulebook(db_session, tmp_path):
    """A synthetic failing scan maps to its synthetic rulebook requirement."""
    project, _dept = _make_project(db_session, "cms-project")

    reports_dir = tmp_path / "reports"
    (reports_dir / "compliance").mkdir(parents=True)
    _write_synthetic_scan_and_rulebook(reports_dir)

    actor_id = _make_actor(db_session, email="hand-check-actor@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.importing,
        triggered_by_user_id=actor_id, reports_path=str(reports_dir),
    )
    db_session.add(scan)
    db_session.flush()

    finished = import_scan_results(db_session, scan_id=scan.id)
    assert finished.status == ScanStatus.succeeded
    scan.status = ScanStatus.succeeded  # seed_rulebook_from_scan re-reads the row; import already set this
    db_session.flush()

    seed_rulebook_from_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    report = compliance_report(
        db_session, project_id=project.id, framework="CIS-Controls", framework_name="CIS Controls v8.1"
    )

    requirement = next(r for r in report["requirements"] if r["requirement_id"] == "12.2")
    assert requirement["status"] == "fail"
    assert "cloudfunction_function_inside_vpc" in requirement["check_ids"]
