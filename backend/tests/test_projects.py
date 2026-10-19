import pytest

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.projects import (
    OrganizationNotFoundError,
    ProjectAlreadyExistsError,
    ProjectNotFoundError,
    delete_project,
    list_projects,
    register_project,
    update_project,
)
from app.services.rbac import ALL_DEPARTMENTS

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


def _make_department(db_session, freshservice_id="1", name="Dept A", deleted=False) -> Department:
    dept = Department(freshservice_id=freshservice_id, name=name, domains=[], deleted=deleted)
    db_session.add(dept)
    db_session.flush()
    return dept


def _make_org(db_session, department, org_id="org-1", name="Org") -> GcpOrganization:
    org = GcpOrganization(org_id=org_id, name=name, department_id=department.id)
    db_session.add(org)
    db_session.flush()
    return org


# ── service layer ────────────────────────────────────────────────────────────


def test_register_project_under_organization(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)

    project = register_project(
        db_session,
        project_id="proj-1",
        gcp_organization_id=org.id,
        target_sa_email="scanner@proj-1.iam.gserviceaccount.com",
        actor_user_id=actor_id,
    )

    assert project.project_id == "proj-1"
    assert project.gcp_organization_id == org.id
    assert project.target_sa_email == "scanner@proj-1.iam.gserviceaccount.com"
    assert project.deleted is False


def test_register_under_missing_organization_raises(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(OrganizationNotFoundError):
        register_project(
            db_session,
            project_id="proj-x",
            gcp_organization_id=999999,
            target_sa_email="x@x.iam.gserviceaccount.com",
            actor_user_id=actor_id,
        )
    assert db_session.query(Project).count() == 0


def test_duplicate_project_id_rejected(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    register_project(
        db_session, project_id="dup", gcp_organization_id=org.id, target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id
    )

    with pytest.raises(ProjectAlreadyExistsError):
        register_project(
            db_session, project_id="dup", gcp_organization_id=org.id, target_sa_email="b@b.iam.gserviceaccount.com", actor_user_id=actor_id
        )
    assert db_session.query(Project).count() == 1


def test_delete_hides_but_preserves_data(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id, target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id
    )

    delete_project(db_session, project_id=project.id, actor_user_id=actor_id)

    visible = list_projects(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert visible == []

    deleted = db_session.get(Project, project.id)
    assert deleted.deleted is True
    assert deleted.project_id == "proj-1"
    assert deleted.target_sa_email == "a@a.iam.gserviceaccount.com"


def test_delete_missing_project_raises(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(ProjectNotFoundError):
        delete_project(db_session, project_id=999999, actor_user_id=actor_id)


def test_delete_then_reregister_same_project_id_succeeds(db_session):
    """Regression: a deleted project's id must not stay globally reserved,
    or "archive then re-add" fails with "already exists"."""
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    first = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id,
        target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
    )
    delete_project(db_session, project_id=first.id, actor_user_id=actor_id)

    second = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id,
        target_sa_email="b@b.iam.gserviceaccount.com", actor_user_id=actor_id,
    )

    assert second.id != first.id
    assert second.deleted is False
    assert db_session.query(Project).filter_by(project_id="proj-1").count() == 2


def test_update_project_changes_org_and_sa_not_project_id(db_session):
    dept = _make_department(db_session)
    org_a = _make_org(db_session, dept, "org-a")
    org_b = _make_org(db_session, dept, "org-b")
    actor_id = _make_actor(db_session)
    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org_a.id,
        target_sa_email="old@old.iam.gserviceaccount.com", actor_user_id=actor_id,
    )

    updated = update_project(
        db_session, project_id=project.id, gcp_organization_id=org_b.id,
        target_sa_email="new@new.iam.gserviceaccount.com", actor_user_id=actor_id,
    )

    assert updated.gcp_organization_id == org_b.id
    assert updated.target_sa_email == "new@new.iam.gserviceaccount.com"
    assert updated.project_id == "proj-1"


def test_update_missing_project_raises(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    with pytest.raises(ProjectNotFoundError):
        update_project(
            db_session, project_id=999999, gcp_organization_id=org.id,
            target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
        )


def test_update_to_missing_organization_raises(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id,
        target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
    )
    with pytest.raises(OrganizationNotFoundError):
        update_project(
            db_session, project_id=project.id, gcp_organization_id=999999,
            target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
        )


def test_deleting_department_hides_its_projects_by_default(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id, target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id
    )

    dept.deleted = True
    db_session.flush()

    assert list_projects(db_session, visible_department_ids=ALL_DEPARTMENTS) == []
    still_there = list_projects(
        db_session, visible_department_ids=ALL_DEPARTMENTS, include_deleted_departments=True
    )
    assert len(still_there) == 1


def test_register_update_and_delete_produce_audit_entries(db_session):
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)

    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id, target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id
    )
    update_project(
        db_session, project_id=project.id, gcp_organization_id=org.id,
        target_sa_email="b@b.iam.gserviceaccount.com", actor_user_id=actor_id,
    )
    delete_project(db_session, project_id=project.id, actor_user_id=actor_id)

    entries = (
        db_session.query(AuditLog)
        .filter_by(target_type="project", target_id=str(project.id))
        .order_by(AuditLog.id)
        .all()
    )
    assert [e.action_type for e in entries] == ["project.create", "project.update", "project.delete"]
    assert all(e.user_id == actor_id for e in entries)
    assert entries[2].before_value == {"deleted": False}
    assert entries[2].after_value == {"deleted": True}


def test_scoped_user_sees_only_projects_of_visible_departments(db_session):
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    org_a = _make_org(db_session, dept_a, "org-a")
    org_b = _make_org(db_session, dept_b, "org-b")
    actor_id = _make_actor(db_session)
    register_project(db_session, project_id="proj-a", gcp_organization_id=org_a.id, target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id)
    register_project(db_session, project_id="proj-b", gcp_organization_id=org_b.id, target_sa_email="b@b.iam.gserviceaccount.com", actor_user_id=actor_id)

    projects = list_projects(db_session, visible_department_ids={dept_a.id})
    assert [p.project_id for p in projects] == ["proj-a"]


# ── API layer ────────────────────────────────────────────────────────────────


def test_non_admin_refused_registering_editing_and_deleting_project(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    actor_id = _make_actor(db_session)
    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org.id,
        target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
    )
    client = sign_in_as(email=VIEWER_EMAIL)

    assert (
        client.post(
            "/api/projects",
            json={"project_id": "proj-2", "gcp_organization_id": org.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
        ).status_code
        == 403
    )
    assert (
        client.put(
            f"/api/projects/{project.id}",
            json={"gcp_organization_id": org.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
        ).status_code
        == 403
    )
    assert client.post(f"/api/projects/{project.id}/delete").status_code == 403


def test_admin_registers_edits_and_deletes_project_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)
    client = sign_in_as(email=ADMIN_EMAIL)

    created = client.post(
        "/api/projects",
        json={"project_id": "proj-1", "gcp_organization_id": org.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    assert created.status_code == 201
    project_id = created.json()["id"]

    updated = client.put(
        f"/api/projects/{project_id}",
        json={"gcp_organization_id": org.id, "target_sa_email": "rotated@rotated.iam.gserviceaccount.com"},
    )
    assert updated.status_code == 200
    assert updated.json()["target_sa_email"] == "rotated@rotated.iam.gserviceaccount.com"
    assert updated.json()["project_id"] == "proj-1"

    deleted = client.post(f"/api/projects/{project_id}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    listing = client.get("/api/projects").json()
    assert listing == []
    listing_all = client.get("/api/projects?include_deleted=true").json()
    assert len(listing_all) == 1

    readded = client.post(
        "/api/projects",
        json={"project_id": "proj-1", "gcp_organization_id": org.id, "target_sa_email": "c@c.iam.gserviceaccount.com"},
    )
    assert readded.status_code == 201


def test_user_calling_project_list_endpoint_sees_only_own_departments(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    org_a = _make_org(db_session, dept_a, "org-a")
    org_b = _make_org(db_session, dept_b, "org-b")
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    admin_client.post(
        "/api/projects",
        json={"project_id": "proj-a", "gcp_organization_id": org_a.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    admin_client.post(
        "/api/projects",
        json={"project_id": "proj-b", "gcp_organization_id": org_b.id, "target_sa_email": "b@b.iam.gserviceaccount.com"},
    )

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_a.id, role=Role.viewer))
    db_session.commit()

    viewer_client = sign_in_as(email=VIEWER_EMAIL)
    response = viewer_client.get("/api/projects")
    assert response.status_code == 200
    assert [p["project_id"] for p in response.json()] == ["proj-a"]


def test_department_admin_registers_edits_and_deletes_project_without_bootstrap(
    db_session, monkeypatch, sign_in_as
):
    """The core fix: a department-scoped Admin (not the global bootstrap
    admin) can fully manage projects under an organization in their own
    department, so they never have to go through a super admin."""
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)

    dept_admin_email = "dept-admin@example.test"
    dept_admin_client = sign_in_as(email=dept_admin_email)
    dept_admin = db_session.query(User).filter_by(email=dept_admin_email).one()
    db_session.add(UserDepartmentRole(user_id=dept_admin.id, department_id=dept.id, role=Role.admin))
    db_session.commit()

    created = dept_admin_client.post(
        "/api/projects",
        json={"project_id": "proj-1", "gcp_organization_id": org.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    assert created.status_code == 201
    project_id = created.json()["id"]

    updated = dept_admin_client.put(
        f"/api/projects/{project_id}",
        json={"gcp_organization_id": org.id, "target_sa_email": "rotated@rotated.iam.gserviceaccount.com"},
    )
    assert updated.status_code == 200

    deleted = dept_admin_client.post(f"/api/projects/{project_id}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_department_editor_cannot_register_project(db_session, monkeypatch, sign_in_as):
    """Only department Admin (not Editor) may register projects — matches
    the role's own stated scope on the Users page."""
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    org = _make_org(db_session, dept)

    editor_email = "dept-editor@example.test"
    editor_client = sign_in_as(email=editor_email)
    editor = db_session.query(User).filter_by(email=editor_email).one()
    db_session.add(UserDepartmentRole(user_id=editor.id, department_id=dept.id, role=Role.editor))
    db_session.commit()

    response = editor_client.post(
        "/api/projects",
        json={"project_id": "proj-1", "gcp_organization_id": org.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    assert response.status_code == 403


def test_department_admin_cannot_register_project_in_other_departments_org(
    db_session, monkeypatch, sign_in_as
):
    """Admin on Dept A does not confer admin on Dept B's organizations."""
    _as_admin(monkeypatch)
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    org_b = _make_org(db_session, dept_b, "org-b")

    admin_a_email = "admin-a@example.test"
    admin_a_client = sign_in_as(email=admin_a_email)
    admin_a = db_session.query(User).filter_by(email=admin_a_email).one()
    db_session.add(UserDepartmentRole(user_id=admin_a.id, department_id=dept_a.id, role=Role.admin))
    db_session.commit()

    response = admin_a_client.post(
        "/api/projects",
        json={"project_id": "proj-1", "gcp_organization_id": org_b.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    assert response.status_code == 403


def test_department_admin_cannot_move_project_into_org_they_do_not_administer(
    db_session, monkeypatch, sign_in_as
):
    _as_admin(monkeypatch)
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    org_a = _make_org(db_session, dept_a, "org-a")
    org_b = _make_org(db_session, dept_b, "org-b")
    actor_id = _make_actor(db_session)
    project = register_project(
        db_session, project_id="proj-1", gcp_organization_id=org_a.id,
        target_sa_email="a@a.iam.gserviceaccount.com", actor_user_id=actor_id,
    )

    admin_a_email = "admin-a@example.test"
    admin_a_client = sign_in_as(email=admin_a_email)
    admin_a = db_session.query(User).filter_by(email=admin_a_email).one()
    db_session.add(UserDepartmentRole(user_id=admin_a.id, department_id=dept_a.id, role=Role.admin))
    db_session.commit()

    response = admin_a_client.put(
        f"/api/projects/{project.id}",
        json={"gcp_organization_id": org_b.id, "target_sa_email": "a@a.iam.gserviceaccount.com"},
    )
    assert response.status_code == 403
