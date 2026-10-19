import csv
from pathlib import Path

import pytest

from app.config import get_settings
from app.models.department import Department
from app.models.finding import Finding, MuteReason
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.importer import import_scan_results
from app.services.findings import (
    FindingNotFoundError,
    department_id_for_finding,
    export_findings_csv,
    get_finding,
    list_findings,
    mute_by_check,
    update_finding,
)
from app.services.rbac import ALL_DEPARTMENTS

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"
EDITOR_EMAIL = "editor@example.test"

COLUMNS = [
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

BASE_ROW = {col: "" for col in COLUMNS}
BASE_ROW.update(
    {
        "PROVIDER": "gcp", "CHECK_ID": "some_check", "CHECK_TITLE": "Some check",
        "STATUS": "FAIL", "MUTED": "False", "SERVICE_NAME": "compute", "SEVERITY": "high",
        "RESOURCE_TYPE": "compute.googleapis.com/Instance", "RESOURCE_UID": "res-1",
        "RESOURCE_NAME": "instance-1", "REGION": "us-central1", "FINDING_UID": "finding-1",
    }
)


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


def _make_project(db_session, project_id="proj-1", freshservice_id="1") -> tuple[Project, Department]:
    dept = Department(freshservice_id=freshservice_id, name=f"Dept {freshservice_id}", domains=[], deleted=False)
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


def _import_one_finding(db_session, project, tmp_path: Path, *, resource_uid="res-1") -> Finding:
    n = db_session.query(Scan).count()
    reports_dir = tmp_path / f"reports-{project.project_id}-{resource_uid}-{n}"
    reports_dir.mkdir()
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, delimiter=";")
        writer.writeheader()
        row = dict(BASE_ROW)
        row["RESOURCE_UID"] = resource_uid
        writer.writerow(row)

    actor_id = _make_actor(db_session, email=f"actor-{project.project_id}-{resource_uid}-{n}@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.importing,
        triggered_by_user_id=actor_id, reports_path=str(reports_dir),
    )
    db_session.add(scan)
    db_session.flush()
    import_scan_results(db_session, scan_id=scan.id)
    return (
        db_session.query(Finding)
        .filter_by(project_id=project.id, resource_uid=resource_uid)
        .one()
    )


def _import_two_findings_same_check(db_session, project, tmp_path: Path) -> tuple[Finding, Finding]:
    """Both rows land in the same scan/CSV, unlike two calls to
    `_import_one_finding` — a resource absent from a *later* scan's CSV
    gets marked RESOURCE_DOES_NOT_EXIST by the importer's absence sweep, which
    would corrupt a same-check bulk-mute test that
    expects both findings to still be FAIL."""
    n = db_session.query(Scan).count()
    reports_dir = tmp_path / f"reports-{project.project_id}-pair-{n}"
    reports_dir.mkdir()
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, delimiter=";")
        writer.writeheader()
        for resource_uid in ("res-a", "res-b"):
            row = dict(BASE_ROW)
            row["RESOURCE_UID"] = resource_uid
            row["FINDING_UID"] = f"finding-{resource_uid}"
            writer.writerow(row)

    actor_id = _make_actor(db_session, email=f"actor-{project.project_id}-pair-{n}@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.importing,
        triggered_by_user_id=actor_id, reports_path=str(reports_dir),
    )
    db_session.add(scan)
    db_session.flush()
    import_scan_results(db_session, scan_id=scan.id)
    findings = (
        db_session.query(Finding)
        .filter_by(project_id=project.id)
        .order_by(Finding.resource_uid)
        .all()
    )
    return findings[0], findings[1]


def _import_findings(db_session, project, tmp_path: Path, overrides: list[dict]) -> list[Finding]:
    """Multiple rows, one scan/CSV, each with its own field overrides on top
    of `BASE_ROW` — the shape filter tests need (several findings that
    differ by severity/service/region/etc. so a filter has something to
    narrow), without corrupting `RESOURCE_UID` uniqueness."""
    n = db_session.query(Scan).count()
    reports_dir = tmp_path / f"reports-{project.project_id}-multi-{n}"
    reports_dir.mkdir()
    with open(reports_dir / "scan.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, delimiter=";")
        writer.writeheader()
        for i, override in enumerate(overrides):
            row = dict(BASE_ROW)
            row["RESOURCE_UID"] = f"multi-res-{n}-{i}"
            row["FINDING_UID"] = f"multi-finding-{n}-{i}"
            row.update(override)
            writer.writerow(row)

    actor_id = _make_actor(db_session, email=f"actor-{project.project_id}-multi-{n}@example.test")
    scan = Scan(
        project_id=project.id, status=ScanStatus.importing,
        triggered_by_user_id=actor_id, reports_path=str(reports_dir),
    )
    db_session.add(scan)
    db_session.flush()
    import_scan_results(db_session, scan_id=scan.id)
    return (
        db_session.query(Finding)
        .filter(Finding.project_id == project.id, Finding.resource_uid.like(f"multi-res-{n}-%"))
        .order_by(Finding.resource_uid)
        .all()
    )


# ── service layer ────────────────────────────────────────────────────────────


def test_list_findings_scoped_by_visible_departments(db_session, tmp_path):
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)

    scoped = list_findings(db_session, visible_department_ids={dept_a.id})
    assert [f.project_id for f in scoped] == [project_a.id]

    every = list_findings(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert len(every) == 2


def test_list_findings_filters_by_project(db_session, tmp_path):
    project_a, _dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)

    scoped = list_findings(db_session, visible_department_ids=ALL_DEPARTMENTS, project_id=project_a.id)
    assert [f.project_id for f in scoped] == [project_a.id]


def test_get_finding_returns_the_finding(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)

    fetched = get_finding(
        db_session, finding_id=finding.id, visible_department_ids=ALL_DEPARTMENTS
    )
    assert fetched.id == finding.id
    assert fetched.check_id == finding.check_id


def test_get_finding_missing_raises(db_session):
    with pytest.raises(FindingNotFoundError):
        get_finding(
            db_session, finding_id=999999, visible_department_ids=ALL_DEPARTMENTS
        )


# ── API layer ────────────────────────────────────────────────────────────────


def test_editor_fetches_a_single_finding_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.get(f"/api/findings/{finding.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == finding.id
    assert body["check_id"] == finding.check_id


def test_get_missing_finding_returns_404(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    client = sign_in_as(email=ADMIN_EMAIL)
    response = client.get("/api/findings/999999")
    assert response.status_code == 404


def test_get_finding_out_of_scope_raises_not_found(db_session, tmp_path):
    """The by-id read must be as scoped as the list read.

    This is the regression guard for a real hole: `get_finding` took no scope
    at all, so any signed-in user could walk integer ids and read every
    finding in the estate — straight past the department join
    `list_findings` spends a join enforcing.
    """
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    finding_b = _import_one_finding(db_session, project_b, tmp_path)

    with pytest.raises(FindingNotFoundError):
        get_finding(
            db_session, finding_id=finding_b.id, visible_department_ids={dept_a.id}
        )


def test_get_finding_in_scope_returns_it(db_session, tmp_path):
    project, dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)

    fetched = get_finding(
        db_session, finding_id=finding.id, visible_department_ids={dept.id}
    )
    assert fetched.id == finding.id


def test_viewer_cannot_read_another_departments_finding_by_id(
    db_session, monkeypatch, sign_in_as, tmp_path
):
    """404, deliberately, not 403.

    A 403 would confirm the id exists and belongs to someone else, which is a
    membership oracle over the whole estate — the endpoint answers exactly as
    it would for an id that was never issued.
    """
    _as_admin(monkeypatch)
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    finding_b = _import_one_finding(db_session, project_b, tmp_path)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_a.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get(f"/api/findings/{finding_b.id}")
    assert response.status_code == 404


def test_user_sees_only_findings_of_visible_departments(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_a.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get("/api/findings")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["project_id"] == project_a.id


def test_admin_sees_every_finding(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project_a, _dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)

    client = sign_in_as(email=ADMIN_EMAIL)
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_finding_response_shape(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    _import_one_finding(db_session, project, tmp_path)

    client = sign_in_as(email=ADMIN_EMAIL)
    response = client.get("/api/findings")
    finding = response.json()[0]
    for field in (
        "check_id", "check_title", "severity", "status", "service_name",
        "subservice_name", "region", "resource_type", "resource_name",
    ):
        assert field in finding


# ── mute overlay (service layer) ────────────────────────────────────────────


def test_muting_requires_a_reason(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")

    with pytest.raises(ValueError):
        update_finding(
            db_session, finding_id=finding.id, muted=True, mute_reason=None,
            note=None, actor_user_id=actor_id,
        )


def test_mute_a_failing_finding_keeps_status_unchanged(db_session, tmp_path):
    """Mute is an orthogonal flag, not a status — a finding can be failing
    and muted at the same time."""
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    assert finding.status == "FAIL"
    actor_id = _make_actor(db_session, email="muter@example.test")

    updated = update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.false_positive, note="checked with infra team",
        actor_user_id=actor_id,
    )

    assert updated.muted is True
    assert updated.mute_reason == MuteReason.false_positive
    assert updated.note == "checked with infra team"
    assert updated.status == "FAIL"  # untouched — status is scan-derived only


def test_unmute_clears_reason_when_caller_sends_none(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")
    update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.risk_accepted, note="tracked in JIRA-1",
        actor_user_id=actor_id,
    )

    unmuted = update_finding(
        db_session, finding_id=finding.id, muted=False, mute_reason=None,
        note=None, actor_user_id=actor_id,
    )

    assert unmuted.muted is False
    assert unmuted.mute_reason is None


def test_update_missing_finding_raises(db_session):
    actor_id = _make_actor(db_session, email="muter@example.test")
    with pytest.raises(FindingNotFoundError):
        update_finding(
            db_session, finding_id=999999, muted=True,
            mute_reason=MuteReason.not_applicable, note=None, actor_user_id=actor_id,
        )


def test_update_finding_produces_audit_entry(db_session, tmp_path):
    from app.models.audit_log import AuditLog

    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")

    update_finding(
        db_session, finding_id=finding.id, muted=True,
        mute_reason=MuteReason.compensating_control, note="mitigated by WAF",
        actor_user_id=actor_id,
    )

    entry = (
        db_session.query(AuditLog)
        .filter_by(target_type="finding", target_id=str(finding.id))
        .one()
    )
    assert entry.action_type == "finding.update"
    assert entry.user_id == actor_id
    assert entry.before_value == {"muted": False, "mute_reason": None, "note": None}
    assert entry.after_value == {
        "muted": True, "mute_reason": "compensating_control", "note": "mitigated by WAF",
    }


def test_mute_by_check_mutes_every_matching_unmuted_finding(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    a, b = _import_two_findings_same_check(db_session, project, tmp_path)
    assert a.check_id == b.check_id == "some_check"
    actor_id = _make_actor(db_session, email="muter@example.test")

    count = mute_by_check(
        db_session, project_id=project.id, check_id="some_check",
        mute_reason=MuteReason.risk_accepted, note="bulk-accepted for this quarter",
        actor_user_id=actor_id,
    )

    assert count == 2
    refreshed_a = db_session.get(Finding, a.id)
    refreshed_b = db_session.get(Finding, b.id)
    for finding in (refreshed_a, refreshed_b):
        assert finding.muted is True
        assert finding.mute_reason == MuteReason.risk_accepted
        assert finding.note == "bulk-accepted for this quarter"
        assert finding.status == "FAIL"  # still untouched — same rule as a single mute


def test_mute_by_check_skips_already_muted_findings(db_session, tmp_path):
    """A category mute applies to the unmuted set only — it must never
    overwrite a judgement a human already made on a specific resource."""
    project, _dept = _make_project(db_session)
    a, b = _import_two_findings_same_check(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")

    update_finding(
        db_session, finding_id=a.id, muted=True, mute_reason=MuteReason.false_positive,
        note="already reviewed individually", actor_user_id=actor_id,
    )

    count = mute_by_check(
        db_session, project_id=project.id, check_id="some_check",
        mute_reason=MuteReason.risk_accepted, note="bulk note", actor_user_id=actor_id,
    )

    assert count == 1
    untouched = db_session.get(Finding, a.id)
    assert untouched.mute_reason == MuteReason.false_positive
    assert untouched.note == "already reviewed individually"
    bulk_muted = db_session.get(Finding, b.id)
    assert bulk_muted.mute_reason == MuteReason.risk_accepted


def test_mute_by_check_only_matches_the_given_project(db_session, tmp_path):
    project_a, _dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    finding_a = _import_one_finding(db_session, project_a, tmp_path)
    finding_b = _import_one_finding(db_session, project_b, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")

    count = mute_by_check(
        db_session, project_id=project_a.id, check_id="some_check",
        mute_reason=MuteReason.not_applicable, note=None, actor_user_id=actor_id,
    )

    assert count == 1
    assert db_session.get(Finding, finding_a.id).muted is True
    assert db_session.get(Finding, finding_b.id).muted is False


def test_editor_mutes_by_check_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    _import_two_findings_same_check(db_session, project, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    editor = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor.id, department_id=dept.id, role=Role.editor))
    db_session.commit()

    client = sign_in_as(email=EDITOR_EMAIL)
    response = client.post(
        "/api/findings/mute-by-check",
        json={
            "project_id": project.id, "check_id": "some_check",
            "mute_reason": "risk_accepted", "note": "quarterly acceptance",
        },
    )
    assert response.status_code == 200
    assert response.json()["muted_count"] == 2


def test_viewer_cannot_mute_by_check(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    _import_one_finding(db_session, project, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.post(
        "/api/findings/mute-by-check",
        json={"project_id": project.id, "check_id": "some_check", "mute_reason": "risk_accepted"},
    )
    assert response.status_code == 403


def test_department_id_for_finding_resolves_through_project(db_session, tmp_path):
    project, dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    assert department_id_for_finding(db_session, finding.id) == dept.id


def test_department_id_for_finding_missing_finding_returns_none(db_session):
    assert department_id_for_finding(db_session, 999999) is None


# ── mute overlay (API layer) ────────────────────────────────────────────────


def test_editor_mutes_a_finding_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    editor = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor.id, department_id=dept.id, role=Role.editor))
    db_session.commit()

    client = sign_in_as(email=EDITOR_EMAIL)
    response = client.patch(
        f"/api/findings/{finding.id}",
        json={"muted": True, "mute_reason": "false_positive", "note": "confirmed safe"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["muted"] is True
    assert body["mute_reason"] == "false_positive"
    assert body["note"] == "confirmed safe"


def test_muting_without_reason_returns_422(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.patch(f"/api/findings/{finding.id}", json={"muted": True, "mute_reason": None})
    assert response.status_code == 422


def test_viewer_cannot_mute_a_finding(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    finding = _import_one_finding(db_session, project, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.patch(
        f"/api/findings/{finding.id}",
        json={"muted": True, "mute_reason": "risk_accepted", "note": None},
    )
    assert response.status_code == 403


def test_editor_of_a_different_department_cannot_mute(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project_a, _dept_a = _make_project(db_session, "proj-a", "1")
    _project_b, dept_b = _make_project(db_session, "proj-b", "2")
    finding = _import_one_finding(db_session, project_a, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    editor_elsewhere = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor_elsewhere)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor_elsewhere.id, department_id=dept_b.id, role=Role.editor))
    db_session.commit()

    client = sign_in_as(email=EDITOR_EMAIL)
    response = client.patch(
        f"/api/findings/{finding.id}",
        json={"muted": True, "mute_reason": "risk_accepted", "note": None},
    )
    assert response.status_code == 403


# ── filtering ───────────────────────────────────────────────────


def test_list_findings_filters_by_every_dimension(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    critical, low = _import_findings(
        db_session, project, tmp_path,
        [
            {
                "SEVERITY": "critical", "STATUS": "FAIL", "SERVICE_NAME": "compute",
                "SUBSERVICE_NAME": "instances", "REGION": "us-central1",
                "RESOURCE_TYPE": "compute.googleapis.com/Instance", "CHECK_ID": "check_a",
                "CHECK_TITLE": "Check A", "RESOURCE_NAME": "vm-critical",
            },
            {
                "SEVERITY": "low", "STATUS": "PASS", "SERVICE_NAME": "storage",
                "SUBSERVICE_NAME": "buckets", "REGION": "europe-west1",
                "RESOURCE_TYPE": "storage.googleapis.com/Bucket", "CHECK_ID": "check_b",
                "CHECK_TITLE": "Check B", "RESOURCE_NAME": "bucket-low",
            },
        ],
    )

    def ids(**kwargs):
        return {f.id for f in list_findings(db_session, visible_department_ids=ALL_DEPARTMENTS, **kwargs)}

    assert ids(severities=["critical"]) == {critical.id}
    assert ids(statuses=["PASS"]) == {low.id}
    assert ids(service_names=["storage"]) == {low.id}
    assert ids(subservice_names=["instances"]) == {critical.id}
    assert ids(regions=["europe-west1"]) == {low.id}
    assert ids(resource_types=["compute.googleapis.com/Instance"]) == {critical.id}
    assert ids(check_ids=["check_b"]) == {low.id}
    assert ids(search="vm-crit") == {critical.id}
    assert ids(search="Check B") == {low.id}
    # Combination: severity + status both narrow onto the same finding.
    assert ids(severities=["critical"], statuses=["FAIL"]) == {critical.id}
    assert ids(severities=["critical"], statuses=["PASS"]) == set()


def test_list_findings_filters_by_muted_and_mute_reason(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    a, b = _import_two_findings_same_check(db_session, project, tmp_path)
    actor_id = _make_actor(db_session, email="muter@example.test")
    update_finding(
        db_session, finding_id=a.id, muted=True, mute_reason=MuteReason.false_positive,
        note=None, actor_user_id=actor_id,
    )

    muted_only = list_findings(db_session, visible_department_ids=ALL_DEPARTMENTS, muted=[True])
    assert {f.id for f in muted_only} == {a.id}

    by_reason = list_findings(
        db_session, visible_department_ids=ALL_DEPARTMENTS, mute_reasons=[MuteReason.false_positive]
    )
    assert {f.id for f in by_reason} == {a.id}


def test_list_findings_orders_most_severe_first(db_session, tmp_path):
    project, _dept = _make_project(db_session)
    _low, _critical = _import_findings(
        db_session, project, tmp_path,
        [
            {"SEVERITY": "low", "CHECK_ID": "check_low"},
            {"SEVERITY": "critical", "CHECK_ID": "check_critical"},
        ],
    )

    ordered = list_findings(db_session, visible_department_ids=ALL_DEPARTMENTS, project_id=project.id)
    assert [f.severity for f in ordered] == ["critical", "low"]


def test_export_matches_filtered_list_exactly(db_session, tmp_path):
    """Regression guard: filter, then export,
    and the file must contain exactly the rows the screen would show —
    including the mute overlay columns."""
    project, _dept = _make_project(db_session)
    critical, low = _import_findings(
        db_session, project, tmp_path,
        [
            {"SEVERITY": "critical", "CHECK_ID": "check_a", "RESOURCE_NAME": "vm-critical"},
            {"SEVERITY": "low", "CHECK_ID": "check_b", "RESOURCE_NAME": "bucket-low"},
        ],
    )
    actor_id = _make_actor(db_session, email="muter@example.test")
    update_finding(
        db_session, finding_id=critical.id, muted=True, mute_reason=MuteReason.risk_accepted,
        note="tracked in JIRA-9", actor_user_id=actor_id,
    )

    on_screen = list_findings(
        db_session, visible_department_ids=ALL_DEPARTMENTS, severities=["critical"]
    )
    assert [f.id for f in on_screen] == [critical.id]

    csv_text = export_findings_csv(
        db_session, visible_department_ids=ALL_DEPARTMENTS, severities=["critical"]
    )
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert len(rows) == len(on_screen) == 1
    row = rows[0]
    assert row["check_id"] == "check_a"
    assert row["resource_name"] == "vm-critical"
    assert row["muted"] == "True"
    assert row["mute_reason"] == "risk_accepted"
    assert row["note"] == "tracked in JIRA-9"
    # The excluded finding must not leak into the file under this filter.
    assert not any(r["check_id"] == "check_b" for r in rows)


def test_export_scoped_by_visible_departments(db_session, tmp_path):
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)

    csv_text = export_findings_csv(db_session, visible_department_ids={dept_a.id})
    rows = list(csv.DictReader(csv_text.splitlines()))
    assert len(rows) == 1
    assert rows[0]["project_id"] == project_a.project_id


def test_viewer_can_export_via_endpoint(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    _import_one_finding(db_session, project, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get(f"/api/findings/export?project_id={project.id}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(response.text.splitlines()))
    assert len(rows) == 1


def test_viewer_cannot_export_outside_visible_departments(db_session, monkeypatch, sign_in_as, tmp_path):
    _as_admin(monkeypatch)
    project_a, dept_a = _make_project(db_session, "proj-a", "1")
    project_b, _dept_b = _make_project(db_session, "proj-b", "2")
    _import_one_finding(db_session, project_a, tmp_path)
    _import_one_finding(db_session, project_b, tmp_path)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_a.id, role=Role.viewer))
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get("/api/findings/export")
    rows = list(csv.DictReader(response.text.splitlines()))
    assert len(rows) == 1
    assert rows[0]["project_id"] == project_a.project_id
