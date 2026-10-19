import pytest

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.users import (
    GrantAlreadyExistsError,
    GrantNotFoundError,
    change_role,
    grant_role,
    list_grants_for_user,
    remove_role,
)

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_department(db_session, freshservice_id="1", name="Dept A") -> Department:
    dept = Department(freshservice_id=freshservice_id, name=name, domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    return dept


def _make_actor(db_session, email="actor@example.test") -> int:
    user = User(email=email, name="Actor")
    db_session.add(user)
    db_session.flush()
    return user.id


# ── service layer ────────────────────────────────────────────────────────────


def test_grant_creates_user_that_did_not_exist_yet(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    grant = grant_role(
        db_session,
        email="brandnew@example.test",
        department_id=dept.id,
        role=Role.editor,
        actor_user_id=actor_id,
    )

    user = db_session.get(User, grant.user_id)
    assert user.email == "brandnew@example.test"
    assert user.last_login_at is None  # never signed in — grant exists ahead of it
    assert grant.role == Role.editor


def test_grant_reuses_existing_user_row(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    existing = User(email="already@example.test", name="Already Here")
    db_session.add(existing)
    db_session.flush()
    existing_id = existing.id

    grant = grant_role(
        db_session, email="already@example.test", department_id=dept.id, role=Role.viewer, actor_user_id=actor_id
    )

    assert grant.user_id == existing_id
    assert db_session.query(User).filter_by(email="already@example.test").count() == 1


def test_granting_twice_on_same_department_rejected(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    grant_role(db_session, email="dup@example.test", department_id=dept.id, role=Role.viewer, actor_user_id=actor_id)

    with pytest.raises(GrantAlreadyExistsError):
        grant_role(
            db_session, email="dup@example.test", department_id=dept.id, role=Role.editor, actor_user_id=actor_id
        )


def test_user_can_hold_grants_on_two_departments(db_session):
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    actor_id = _make_actor(db_session)

    grant_role(db_session, email="multi@example.test", department_id=dept_a.id, role=Role.viewer, actor_user_id=actor_id)
    grant = grant_role(
        db_session, email="multi@example.test", department_id=dept_b.id, role=Role.admin, actor_user_id=actor_id
    )

    grants = list_grants_for_user(db_session, grant.user_id)
    assert {(g.department_id, g.role) for g in grants} == {
        (dept_a.id, Role.viewer),
        (dept_b.id, Role.admin),
    }


def test_change_role_updates_existing_grant(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    grant = grant_role(
        db_session, email="promote@example.test", department_id=dept.id, role=Role.viewer, actor_user_id=actor_id
    )

    updated = change_role(
        db_session, user_id=grant.user_id, department_id=dept.id, role=Role.editor, actor_user_id=actor_id
    )

    assert updated.role == Role.editor


def test_change_role_without_existing_grant_raises(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    with pytest.raises(GrantNotFoundError):
        change_role(db_session, user_id=999999, department_id=dept.id, role=Role.editor, actor_user_id=actor_id)


def test_remove_role_deletes_grant(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)
    grant = grant_role(
        db_session, email="removeme@example.test", department_id=dept.id, role=Role.viewer, actor_user_id=actor_id
    )

    remove_role(db_session, user_id=grant.user_id, department_id=dept.id, actor_user_id=actor_id)

    assert (
        db_session.query(UserDepartmentRole)
        .filter_by(user_id=grant.user_id, department_id=dept.id)
        .count()
        == 0
    )


def test_remove_role_without_existing_grant_raises(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    with pytest.raises(GrantNotFoundError):
        remove_role(db_session, user_id=999999, department_id=dept.id, actor_user_id=actor_id)


def test_grant_change_remove_each_produce_an_audit_entry(db_session):
    dept = _make_department(db_session)
    actor_id = _make_actor(db_session)

    grant = grant_role(
        db_session, email="audited@example.test", department_id=dept.id, role=Role.viewer, actor_user_id=actor_id
    )
    change_role(db_session, user_id=grant.user_id, department_id=dept.id, role=Role.editor, actor_user_id=actor_id)
    remove_role(db_session, user_id=grant.user_id, department_id=dept.id, actor_user_id=actor_id)

    target_id = f"{grant.user_id}:{dept.id}"
    entries = (
        db_session.query(AuditLog)
        .filter_by(target_type="user_department_role", target_id=target_id)
        .order_by(AuditLog.id)
        .all()
    )
    assert [e.action_type for e in entries] == [
        "user_department_role.grant",
        "user_department_role.change",
        "user_department_role.remove",
    ]
    assert all(e.user_id == actor_id for e in entries)
    assert entries[0].before_value is None
    assert entries[0].after_value["role"] == "viewer"
    assert entries[1].before_value == {"role": "viewer"}
    assert entries[1].after_value == {"role": "editor"}
    assert entries[2].before_value == {"role": "editor"}
    assert entries[2].after_value is None


# ── API layer ────────────────────────────────────────────────────────────────


def test_non_admin_refused_by_grant_endpoints(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=VIEWER_EMAIL)

    assert client.get("/api/users").status_code == 403
    assert (
        client.post("/api/users", json={"email": "x@example.test", "department_id": dept.id, "role": "viewer"}).status_code
        == 403
    )
    assert client.put("/api/users/1/roles/1", json={"role": "editor"}).status_code == 403
    assert client.delete("/api/users/1/roles/1").status_code == 403


def test_admin_grants_role_and_it_is_immediately_visible(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post(
        "/api/users", json={"email": "newgrant@example.test", "department_id": dept.id, "role": "viewer"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "newgrant@example.test"
    assert body["grants"] == [{"department_id": dept.id, "role": "viewer"}]

    listing = client.get("/api/users").json()
    matched = next(u for u in listing if u["email"] == "newgrant@example.test")
    assert matched["grants"] == [{"department_id": dept.id, "role": "viewer"}]


def test_admin_can_change_and_remove_a_grant(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    client = sign_in_as(email=ADMIN_EMAIL)
    created = client.post(
        "/api/users", json={"email": "editme@example.test", "department_id": dept.id, "role": "viewer"}
    ).json()
    user_id = created["id"]

    changed = client.put(f"/api/users/{user_id}/roles/{dept.id}", json={"role": "admin"})
    assert changed.status_code == 200
    assert changed.json()["grants"] == [{"department_id": dept.id, "role": "admin"}]

    removed = client.delete(f"/api/users/{user_id}/roles/{dept.id}")
    assert removed.status_code == 200
    assert removed.json()["grants"] == []


def test_first_sign_in_after_grant_needs_no_further_step(db_session, monkeypatch, sign_in_as):
    """The grant is created for an email before that person ever signs in;
    their first OAuth callback must reuse the same row rather than creating
    a second, ungranted one."""
    _as_admin(monkeypatch)
    dept = _make_department(db_session)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    admin_client.post(
        "/api/users", json={"email": "preexisting@example.test", "department_id": dept.id, "role": "editor"}
    )

    pre_login_user = db_session.query(User).filter_by(email="preexisting@example.test").one()
    assert pre_login_user.last_login_at is None

    sign_in_as(email="preexisting@example.test", name="Real Name")

    post_login_user = db_session.query(User).filter_by(email="preexisting@example.test").one()
    assert post_login_user.id == pre_login_user.id
    assert post_login_user.name == "Real Name"
    assert post_login_user.last_login_at is not None

    grants = list_grants_for_user(db_session, post_login_user.id)
    assert [(g.department_id, g.role) for g in grants] == [(dept.id, Role.editor)]
