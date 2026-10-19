import pytest

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.scans import (
    ProjectNotOnboardedError,
    ScanNotCancellableError,
    ScanNotFoundError,
    cancel_scan,
    department_id_for_project,
    finalize_scan_failure,
    get_scan,
    is_stale,
    list_scans,
    mark_importing,
    mark_running,
    submit_scan,
)
from app.services.rbac import ALL_DEPARTMENTS

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"
EDITOR_EMAIL = "editor@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


def _make_project(db_session, project_id="proj-1", deleted=False) -> Project:
    dept = Department(freshservice_id=project_id, name="Dept", domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    org = GcpOrganization(org_id=f"org-{project_id}", name="Org", department_id=dept.id)
    db_session.add(org)
    db_session.flush()
    project = Project(
        project_id=project_id,
        gcp_organization_id=org.id,
        target_sa_email=f"scanner@{project_id}.iam.gserviceaccount.com",
        deleted=deleted,
    )
    db_session.add(project)
    db_session.flush()
    return project, dept


# ── service layer ────────────────────────────────────────────────────────────


def test_submit_scan_creates_queued_row_with_snapshotted_sa(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)

    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)

    assert scan.status == ScanStatus.queued
    assert scan.project_id == project.id
    assert scan.sa_impersonated == project.target_sa_email
    assert scan.triggered_by_user_id == actor_id
    assert scan.triggered_at is not None


def test_submit_scan_against_missing_project_rejected(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(ProjectNotOnboardedError):
        submit_scan(db_session, project_id=999999, actor_user_id=actor_id)
    assert db_session.query(Scan).count() == 0


def test_submit_scan_against_deleted_project_rejected(db_session):
    project, _dept = _make_project(db_session, deleted=True)
    actor_id = _make_actor(db_session)
    with pytest.raises(ProjectNotOnboardedError):
        submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    assert db_session.query(Scan).count() == 0


def test_submit_scan_produces_audit_entry(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)

    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)

    entries = db_session.query(AuditLog).filter_by(target_type="scan", target_id=str(scan.id)).all()
    assert [e.action_type for e in entries] == ["scan.submit"]
    assert entries[0].user_id == actor_id
    assert entries[0].after_value == {"project_id": project.id, "status": "queued"}


def test_department_id_for_project_resolves_through_organization(db_session):
    project, dept = _make_project(db_session)
    assert department_id_for_project(db_session, project.id) == dept.id


def test_department_id_for_project_missing_project_returns_none(db_session):
    assert department_id_for_project(db_session, 999999) is None


def test_get_scan_missing_raises(db_session):
    with pytest.raises(ScanNotFoundError):
        get_scan(
            db_session, scan_id=999999, visible_department_ids=ALL_DEPARTMENTS
        )


def test_get_scan_out_of_scope_raises_not_found(db_session):
    """Regression guard: the by-id read used to take no scope at all, so any
    signed-in user could walk integer ids across every department. 404 rather
    than 403 on purpose — a 403 would confirm the id exists and belongs to
    someone else."""
    project_a, dept_a = _make_project(db_session, "proj-a")
    project_b, _dept_b = _make_project(db_session, "proj-b")
    scan_b = Scan(
        project_id=project_b.id,
        status=ScanStatus.succeeded,
        triggered_by_user_id=_make_actor(db_session, "actor-scope@example.test"),
    )
    db_session.add(scan_b)
    db_session.commit()

    with pytest.raises(ScanNotFoundError):
        get_scan(db_session, scan_id=scan_b.id, visible_department_ids={dept_a.id})

    assert (
        get_scan(db_session, scan_id=scan_b.id, visible_department_ids=ALL_DEPARTMENTS).id
        == scan_b.id
    )


def test_list_scans_scoped_by_visible_departments(db_session):
    project_a, dept_a = _make_project(db_session, "proj-a")
    project_b, dept_b = _make_project(db_session, "proj-b")
    actor_id = _make_actor(db_session)
    submit_scan(db_session, project_id=project_a.id, actor_user_id=actor_id)
    submit_scan(db_session, project_id=project_b.id, actor_user_id=actor_id)

    scoped = list_scans(db_session, visible_department_ids={dept_a.id})
    assert [s.project_id for s in scoped] == [project_a.id]

    every = list_scans(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert len(every) == 2


def test_mark_running_then_mark_importing(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)

    mark_running(db_session, scan_id=scan.id, container_id="abc123", reports_path="/reports/1")
    running = db_session.get(Scan, scan.id)
    assert running.status == ScanStatus.running
    assert running.started_at is not None
    assert running.container_id == "abc123"

    mark_importing(db_session, scan_id=scan.id, exit_code=0)
    finished = db_session.get(Scan, scan.id)
    assert finished.status == ScanStatus.importing
    assert finished.completed_at is not None
    assert finished.exit_code == 0


def test_finalize_failure_marks_failed(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")

    finalize_scan_failure(db_session, scan_id=scan.id, exit_code=1, timed_out=False, error_message="exit code 1")
    finished = db_session.get(Scan, scan.id)
    assert finished.status == ScanStatus.failed
    assert finished.error_message == "exit code 1"


def test_finalize_failure_timeout_marks_timeout_regardless_of_exit_code(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")

    finalize_scan_failure(db_session, scan_id=scan.id, exit_code=None, timed_out=True, error_message="timed out")
    finished = db_session.get(Scan, scan.id)
    assert finished.status == ScanStatus.timeout


def test_is_stale_true_only_for_running_past_ceiling(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)

    assert is_stale(scan, timeout_seconds=7200) is False

    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")
    running = db_session.get(Scan, scan.id)
    assert is_stale(running, timeout_seconds=7200) is False
    assert is_stale(running, timeout_seconds=-1) is True

    mark_importing(db_session, scan_id=scan.id, exit_code=0)
    finished = db_session.get(Scan, scan.id)
    assert is_stale(finished, timeout_seconds=-1) is False


def test_cancel_scan_marks_cancelled_with_audit_entry(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")

    cancelled = cancel_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)
    assert cancelled.status == ScanStatus.cancelled
    assert cancelled.completed_at is not None

    entries = db_session.query(AuditLog).filter_by(target_type="scan", target_id=str(scan.id)).all()
    assert entries[-1].action_type == "scan.cancel"
    assert entries[-1].before_value == {"status": "running"}
    assert entries[-1].after_value == {"status": "cancelled"}


def test_cancel_scan_on_terminal_scan_rejected(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")
    mark_importing(db_session, scan_id=scan.id, exit_code=0)
    finalize_scan_failure(db_session, scan_id=scan.id, exit_code=1, timed_out=False, error_message="x")

    with pytest.raises(ScanNotCancellableError):
        cancel_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)


def test_cancel_scan_missing_raises(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(ScanNotFoundError):
        cancel_scan(db_session, scan_id=999999, actor_user_id=actor_id)


def test_finalize_failure_does_not_clobber_a_cancelled_scan(db_session):
    """The orphan-recovery race this exists for: an operator cancels a scan
    while its container is still running (killing the container unblocks
    the in-flight task's `docker wait`), and that task then reaches its own
    finalize call. The cancel already wrote the terminal state — the task
    must not overwrite "cancelled" with "failed"."""
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")

    cancel_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    result = finalize_scan_failure(
        db_session, scan_id=scan.id, exit_code=137, timed_out=False, error_message="killed"
    )
    assert result.status == ScanStatus.cancelled
    assert result.error_message == "Cancelled from the UI."


def test_mark_importing_does_not_clobber_a_cancelled_scan(db_session):
    project, _dept = _make_project(db_session)
    actor_id = _make_actor(db_session)
    scan = submit_scan(db_session, project_id=project.id, actor_user_id=actor_id)
    mark_running(db_session, scan_id=scan.id, container_id="abc", reports_path="/reports/1")

    cancel_scan(db_session, scan_id=scan.id, actor_user_id=actor_id)

    result = mark_importing(db_session, scan_id=scan.id, exit_code=0)
    assert result.status == ScanStatus.cancelled


# ── API layer ────────────────────────────────────────────────────────────────


def test_editor_submits_scan_and_task_is_enqueued(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    admin_client = sign_in_as(email=ADMIN_EMAIL)

    editor = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor.id, department_id=dept.id, role=Role.editor))
    db_session.commit()

    delays = []
    monkeypatch.setattr(
        "app.api.routers.scans.run_scan_task.delay", lambda scan_id: delays.append(scan_id)
    )

    editor_client = sign_in_as(email=EDITOR_EMAIL)
    response = editor_client.post("/api/scans", json={"project_id": project.id})
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    assert body["project_id"] == project.id
    assert delays == [body["id"]]


def test_viewer_cannot_submit_scan(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)

    viewer_client = sign_in_as(email=VIEWER_EMAIL)
    response = viewer_client.post("/api/scans", json={"project_id": project.id})
    assert response.status_code == 403
    assert db_session.query(Scan).count() == 0


def test_user_with_no_grant_on_project_department_refused(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept_a = _make_project(db_session, "proj-a")
    _other_project, dept_b = _make_project(db_session, "proj-b")
    sign_in_as(email=ADMIN_EMAIL)

    editor_elsewhere = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor_elsewhere)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor_elsewhere.id, department_id=dept_b.id, role=Role.editor))
    db_session.commit()

    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)

    client = sign_in_as(email=EDITOR_EMAIL)
    response = client.post("/api/scans", json={"project_id": project.id})
    assert response.status_code == 403


def test_submitting_unregistered_project_id_refused_with_explanation(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/scans", json={"project_id": 999999})
    assert response.status_code == 400
    assert "not onboarded" in response.json()["detail"]


def test_submitting_deleted_project_refused(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session, deleted=True)
    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/scans", json={"project_id": project.id})
    assert response.status_code == 400


def test_get_scan_returns_current_status(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)
    client = sign_in_as(email=ADMIN_EMAIL)

    created = client.post("/api/scans", json={"project_id": project.id}).json()
    fetched = client.get(f"/api/scans/{created['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "queued"


def test_get_scan_log_before_any_run_is_empty(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)
    client = sign_in_as(email=ADMIN_EMAIL)

    created = client.post("/api/scans", json={"project_id": project.id}).json()
    log = client.get(f"/api/scans/{created['id']}/log")
    assert log.status_code == 200
    assert log.json()["log"] == ""


def test_editor_cancels_scan_and_cleanup_is_enqueued(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    admin_client = sign_in_as(email=ADMIN_EMAIL)

    editor = User(email=EDITOR_EMAIL, name="Editor")
    db_session.add(editor)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=editor.id, department_id=dept.id, role=Role.editor))
    db_session.commit()

    created = admin_client.post("/api/scans", json={"project_id": project.id}).json()
    mark_running(db_session, scan_id=created["id"], container_id="abc", reports_path="/reports/1")
    db_session.commit()

    cleanups = []
    monkeypatch.setattr(
        "app.api.routers.scans.cleanup_cancelled_scan.delay",
        lambda scan_id, container_id: cleanups.append((scan_id, container_id)),
    )

    editor_client = sign_in_as(email=EDITOR_EMAIL)
    response = editor_client.post(f"/api/scans/{created['id']}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert cleanups == [(created["id"], "abc")]


def test_viewer_cannot_cancel_scan(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, dept = _make_project(db_session)
    admin_client = sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept.id, role=Role.viewer))
    db_session.commit()

    created = admin_client.post("/api/scans", json={"project_id": project.id}).json()

    viewer_client = sign_in_as(email=VIEWER_EMAIL)
    response = viewer_client.post(f"/api/scans/{created['id']}/cancel")
    assert response.status_code == 403


def test_cancelling_a_terminal_scan_returns_409(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    project, _dept = _make_project(db_session)
    monkeypatch.setattr("app.api.routers.scans.run_scan_task.delay", lambda scan_id: None)
    client = sign_in_as(email=ADMIN_EMAIL)

    created = client.post("/api/scans", json={"project_id": project.id}).json()
    mark_running(db_session, scan_id=created["id"], container_id="abc", reports_path="/reports/1")
    finalize_scan_failure(db_session, scan_id=created["id"], exit_code=1, timed_out=False, error_message="x")
    db_session.commit()

    response = client.post(f"/api/scans/{created['id']}/cancel")
    assert response.status_code == 409


def test_cancelling_missing_scan_returns_404(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    client = sign_in_as(email=ADMIN_EMAIL)
    response = client.post("/api/scans/999999/cancel")
    assert response.status_code == 404
