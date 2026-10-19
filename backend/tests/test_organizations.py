import pytest

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.organizations import (
    DepartmentNotFoundError,
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    delete_organization,
    list_organizations,
    register_organization,
    update_organization,
)
from app.services.rbac import ALL_DEPARTMENTS

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_department(db_session, freshservice_id="1", name="Dept A", deleted=False) -> Department:
    dept = Department(freshservice_id=freshservice_id, name=name, domains=[], deleted=deleted)
    db_session.add(dept)
    db_session.flush()
    return dept


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


# ── service layer ────────────────────────────────────────────────────────────


def test_register_organization_under_department(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    org = register_organization(
        db_session, org_id="org-1", name="Sample Organization", department_id=dept.id, actor_user_id=actor_id
    )

    assert org.org_id == "org-1"
    assert org.name == "Sample Organization"
    assert org.department_id == dept.id


def test_department_can_hold_several_organizations(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    register_organization(db_session, org_id="org-1", name="Org One", department_id=dept.id, actor_user_id=actor_id)
    register_organization(db_session, org_id="org-2", name="Org Two", department_id=dept.id, actor_user_id=actor_id)

    orgs = list_organizations(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert {o.org_id for o in orgs} == {"org-1", "org-2"}


def test_register_under_missing_department_raises(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(DepartmentNotFoundError):
        register_organization(
            db_session, org_id="org-x", name="X", department_id=999999, actor_user_id=actor_id
        )
    assert db_session.query(GcpOrganization).count() == 0


def test_duplicate_org_id_rejected(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    register_organization(db_session, org_id="dup", name="First", department_id=dept.id, actor_user_id=actor_id)

    with pytest.raises(OrganizationAlreadyExistsError):
        register_organization(
            db_session, org_id="dup", name="Second", department_id=dept.id, actor_user_id=actor_id
        )
    assert db_session.query(GcpOrganization).count() == 1


def test_delete_then_reregister_same_org_id_succeeds(db_session):
    """Regression: a deleted organization's id
    must not stay globally reserved."""
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    first = register_organization(
        db_session, org_id="dup", name="First", department_id=dept.id, actor_user_id=actor_id
    )
    delete_organization(db_session, organization_id=first.id, actor_user_id=actor_id)

    second = register_organization(
        db_session, org_id="dup", name="Second", department_id=dept.id, actor_user_id=actor_id
    )

    assert second.id != first.id
    assert second.deleted is False
    assert db_session.query(GcpOrganization).filter_by(org_id="dup").count() == 2


def test_update_organization_changes_name_and_department_not_org_id(db_session):
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    actor_id = _make_actor(db_session)
    org = register_organization(
        db_session, org_id="org-1", name="Old Name", department_id=dept_a.id, actor_user_id=actor_id
    )

    updated = update_organization(
        db_session, organization_id=org.id, name="New Name", department_id=dept_b.id, actor_user_id=actor_id
    )

    assert updated.name == "New Name"
    assert updated.department_id == dept_b.id
    assert updated.org_id == "org-1"


def test_update_missing_organization_raises(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    with pytest.raises(OrganizationNotFoundError):
        update_organization(
            db_session, organization_id=999999, name="X", department_id=dept.id, actor_user_id=actor_id
        )


def test_update_to_missing_department_raises(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    org = register_organization(
        db_session, org_id="org-1", name="Org", department_id=dept.id, actor_user_id=actor_id
    )
    with pytest.raises(DepartmentNotFoundError):
        update_organization(
            db_session, organization_id=org.id, name="Org", department_id=999999, actor_user_id=actor_id
        )


def test_delete_missing_organization_raises(db_session):
    actor_id = _make_actor(db_session)
    with pytest.raises(OrganizationNotFoundError):
        delete_organization(db_session, organization_id=999999, actor_user_id=actor_id)


def test_delete_hides_but_preserves_data(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    org = register_organization(
        db_session, org_id="org-1", name="Org One", department_id=dept.id, actor_user_id=actor_id
    )

    delete_organization(db_session, organization_id=org.id, actor_user_id=actor_id)

    visible = list_organizations(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert visible == []

    deleted = db_session.get(GcpOrganization, org.id)
    assert deleted.deleted is True
    assert deleted.name == "Org One"
    assert deleted.org_id == "org-1"


def test_update_and_delete_produce_audit_entries(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    org = register_organization(
        db_session, org_id="org-1", name="Org One", department_id=dept.id, actor_user_id=actor_id
    )
    update_organization(
        db_session, organization_id=org.id, name="Org Two", department_id=dept.id, actor_user_id=actor_id
    )
    delete_organization(db_session, organization_id=org.id, actor_user_id=actor_id)

    entries = (
        db_session.query(AuditLog)
        .filter_by(target_type="gcp_organization", target_id=str(org.id))
        .order_by(AuditLog.id)
        .all()
    )
    assert [e.action_type for e in entries] == [
        "gcp_organization.create",
        "gcp_organization.update",
        "gcp_organization.delete",
    ]
    assert entries[2].before_value == {"deleted": False}
    assert entries[2].after_value == {"deleted": True}


def test_deleting_department_hides_its_organizations_by_default(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    register_organization(db_session, org_id="org-1", name="Org One", department_id=dept.id, actor_user_id=actor_id)

    dept.deleted = True
    db_session.flush()

    visible = list_organizations(db_session, visible_department_ids=ALL_DEPARTMENTS)
    assert visible == []

    still_there = list_organizations(
        db_session, visible_department_ids=ALL_DEPARTMENTS, include_deleted_departments=True
    )
    assert len(still_there) == 1
    assert still_there[0].name == "Org One"


def test_register_produces_audit_entry(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    org = register_organization(
        db_session, org_id="org-1", name="Sample Organization", department_id=dept.id, actor_user_id=actor_id
    )

    entry = (
        db_session.query(AuditLog)
        .filter_by(target_type="gcp_organization", target_id=str(org.id))
        .one()
    )
    assert entry.action_type == "gcp_organization.create"
    assert entry.user_id == actor_id
    assert entry.before_value is None
    assert entry.after_value == {"org_id": "org-1", "name": "Sample Organization", "department_id": dept.id}


def test_scoped_user_sees_only_organizations_of_visible_departments(db_session):
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    actor_id = _make_actor(db_session)
    register_organization(db_session, org_id="org-a", name="Org A", department_id=dept_a.id, actor_user_id=actor_id)
    register_organization(db_session, org_id="org-b", name="Org B", department_id=dept_b.id, actor_user_id=actor_id)

    orgs = list_organizations(db_session, visible_department_ids={dept_a.id})
    assert [o.org_id for o in orgs] == ["org-a"]


# ── API layer ────────────────────────────────────────────────────────────────


def test_non_admin_refused_registering_organization(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=VIEWER_EMAIL)

    response = client.post("/api/organizations", json={"org_id": "org-1", "name": "Org", "department_id": dept.id})
    assert response.status_code == 403


def test_admin_registers_organization_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/organizations", json={"org_id": "org-1", "name": "Org", "department_id": dept.id})
    assert response.status_code == 201
    assert response.json()["name"] == "Org"


def test_admin_edits_and_deletes_organization_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=ADMIN_EMAIL)
    created = client.post(
        "/api/organizations", json={"org_id": "org-1", "name": "Org", "department_id": dept.id}
    ).json()

    updated = client.put(f"/api/organizations/{created['id']}", json={"name": "Renamed", "department_id": dept.id})
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["org_id"] == "org-1"

    deleted = client.post(f"/api/organizations/{created['id']}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    listing = client.get("/api/organizations").json()
    assert listing == []

    readded = client.post(
        "/api/organizations", json={"org_id": "org-1", "name": "Org", "department_id": dept.id}
    )
    assert readded.status_code == 201


def test_non_admin_refused_editing_and_deleting_organization(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    created = admin_client.post(
        "/api/organizations", json={"org_id": "org-1", "name": "Org", "department_id": dept.id}
    ).json()

    viewer_client = sign_in_as(email=VIEWER_EMAIL)
    assert (
        viewer_client.put(
            f"/api/organizations/{created['id']}", json={"name": "Renamed", "department_id": dept.id}
        ).status_code
        == 403
    )
    assert viewer_client.post(f"/api/organizations/{created['id']}/delete").status_code == 403


def test_user_calling_list_endpoint_sees_only_own_departments(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    admin_client.post("/api/organizations", json={"org_id": "org-a", "name": "Org A", "department_id": dept_a.id})
    admin_client.post("/api/organizations", json={"org_id": "org-b", "name": "Org B", "department_id": dept_b.id})

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.flush()
    db_session.add(UserDepartmentRole(user_id=viewer.id, department_id=dept_a.id, role=Role.viewer))
    db_session.flush()
    db_session.commit()

    viewer_client = sign_in_as(email=VIEWER_EMAIL)
    response = viewer_client.get("/api/organizations")
    assert response.status_code == 200
    assert [o["org_id"] for o in response.json()] == ["org-a"]
