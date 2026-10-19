import pytest
from sqlalchemy.exc import IntegrityError

from app.config import get_settings
from app.integrations.freshservice import (
    FreshserviceDepartment,
    FreshserviceNotFoundError,
    FreshserviceUnavailableError,
)
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services import audit
from app.services.departments import (
    DepartmentNotFoundError,
    DepartmentAlreadyExistsError,
    add_department,
    delete_department,
    list_departments,
    refresh_department,
)
from app.services.users import upsert_user_from_login

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "engineer@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_user(db_session, email="actor@example.test"):
    return upsert_user_from_login(db_session, email=email, name="Actor").id


def _fake_fetch(freshservice_id, *, domain, api_key, timeout=10.0):
    return FreshserviceDepartment(
        freshservice_id=freshservice_id, name="Sample Organization", domains=["sample.example.test", "support.example.test"]
    )


# ── service layer ────────────────────────────────────────────────────────────


def test_add_department_stores_only_id_name_domains(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin = sign_in_as(email=ADMIN_EMAIL).get("/api/auth/me").json()
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)

    from app.models.user import User

    actor = db_session.query(User).filter_by(email=admin["email"]).one()

    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor.id, settings=get_settings()
    )

    assert dept.freshservice_id == "42"
    assert dept.name == "Sample Organization"
    assert dept.domains == ["sample.example.test", "support.example.test"]
    assert dept.deleted is False
    # Only these columns exist on the model at all — there is no field to
    # smuggle extra Freshservice data into.
    assert set(Department.__table__.columns.keys()) == {
        "id",
        "freshservice_id",
        "name",
        "domains",
        "deleted",
        "created_at",
    }


def test_unrecognised_identifier_refused_creates_nothing(db_session, monkeypatch):
    def _not_found(freshservice_id, *, domain, api_key, timeout=10.0):
        raise FreshserviceNotFoundError(freshservice_id)

    monkeypatch.setattr("app.services.departments.fetch_department", _not_found)

    with pytest.raises(FreshserviceNotFoundError):
        add_department(db_session, freshservice_id="999", actor_user_id=1, settings=get_settings())

    assert db_session.query(Department).count() == 0


def test_freshservice_outage_refused_cleanly(db_session, monkeypatch):
    def _unavailable(freshservice_id, *, domain, api_key, timeout=10.0):
        raise FreshserviceUnavailableError("Freshservice returned 500")

    monkeypatch.setattr("app.services.departments.fetch_department", _unavailable)

    with pytest.raises(FreshserviceUnavailableError):
        add_department(db_session, freshservice_id="1", actor_user_id=1, settings=get_settings())

    assert db_session.query(Department).count() == 0


def test_duplicate_department_rejected(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)

    add_department(db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings())

    with pytest.raises(DepartmentAlreadyExistsError):
        add_department(
            db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
        )

    assert db_session.query(Department).count() == 1


def test_delete_hides_but_preserves_data(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )

    delete_department(db_session, department_id=dept.id, actor_user_id=actor_id)

    visible = list_departments(db_session, include_deleted=False)
    assert dept.id not in {d.id for d in visible}

    deleted = db_session.get(Department, dept.id)
    assert deleted.deleted is True
    assert deleted.name == "Sample Organization"
    assert deleted.domains == ["sample.example.test", "support.example.test"]
    assert deleted.freshservice_id == "42"


def test_delete_then_readd_same_freshservice_id_succeeds(db_session, monkeypatch):
    """Regression: a deleted department's id must
    not stay globally reserved."""
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    first = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )
    delete_department(db_session, department_id=first.id, actor_user_id=actor_id)

    second = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )

    assert second.id != first.id
    assert second.deleted is False
    assert db_session.query(Department).filter_by(freshservice_id="42").count() == 2


def test_add_and_delete_produce_audit_entries(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)

    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )
    delete_department(db_session, department_id=dept.id, actor_user_id=actor_id)

    entries = (
        db_session.query(AuditLog)
        .filter_by(target_type="department", target_id=str(dept.id))
        .order_by(AuditLog.id)
        .all()
    )
    assert [e.action_type for e in entries] == ["department.create", "department.delete"]
    assert all(e.user_id == actor_id for e in entries)
    assert entries[0].before_value is None
    assert entries[0].after_value["name"] == "Sample Organization"
    assert entries[1].before_value == {"deleted": False}
    assert entries[1].after_value == {"deleted": True}


def test_refresh_pulls_new_domains_from_freshservice(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )
    assert dept.domains == ["sample.example.test", "support.example.test"]

    def _updated_fetch(freshservice_id, *, domain, api_key, timeout=10.0):
        return FreshserviceDepartment(
            freshservice_id=freshservice_id,
            name="Sample Organization",
            domains=["sample.example.test", "support.example.test", "new.example.test"],
        )

    monkeypatch.setattr("app.services.departments.fetch_department", _updated_fetch)
    refreshed = refresh_department(
        db_session, department_id=dept.id, actor_user_id=actor_id, settings=get_settings()
    )

    assert refreshed.domains == ["sample.example.test", "support.example.test", "new.example.test"]
    assert refreshed.freshservice_id == "42"  # the fetch key itself never changes


def test_refresh_uses_stored_freshservice_id_not_caller_input(db_session, monkeypatch):
    """Refresh always re-fetches by the department's own stored
    freshservice_id — there is no way to point a refresh at a different
    upstream record."""
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )

    seen_ids = []

    def _spy_fetch(freshservice_id, *, domain, api_key, timeout=10.0):
        seen_ids.append(freshservice_id)
        return _fake_fetch(freshservice_id, domain=domain, api_key=api_key)

    monkeypatch.setattr("app.services.departments.fetch_department", _spy_fetch)
    refresh_department(
        db_session, department_id=dept.id, actor_user_id=actor_id, settings=get_settings()
    )

    assert seen_ids == ["42"]


def test_refresh_missing_department_raises(db_session):
    """Named error, not a bare ValueError — it carries its own 404 now, so the
    router needs no `except` for it."""
    with pytest.raises(DepartmentNotFoundError):
        refresh_department(
            db_session, department_id=999999, actor_user_id=1, settings=get_settings()
        )


def test_refresh_not_found_upstream_leaves_department_untouched(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )

    def _not_found(freshservice_id, *, domain, api_key, timeout=10.0):
        raise FreshserviceNotFoundError(freshservice_id)

    monkeypatch.setattr("app.services.departments.fetch_department", _not_found)
    with pytest.raises(FreshserviceNotFoundError):
        refresh_department(
            db_session, department_id=dept.id, actor_user_id=actor_id, settings=get_settings()
        )

    unchanged = db_session.get(Department, dept.id)
    assert unchanged.name == "Sample Organization"
    assert unchanged.domains == ["sample.example.test", "support.example.test"]


def test_refresh_produces_audit_entry_only_when_something_changed(db_session, monkeypatch):
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    actor_id = _make_user(db_session)
    dept = add_department(
        db_session, freshservice_id="42", actor_user_id=actor_id, settings=get_settings()
    )

    # No-op refresh: same data, no audit entry.
    refresh_department(
        db_session, department_id=dept.id, actor_user_id=actor_id, settings=get_settings()
    )
    assert (
        db_session.query(AuditLog)
        .filter_by(target_type="department", target_id=str(dept.id), action_type="department.refresh")
        .count()
        == 0
    )

    def _updated_fetch(freshservice_id, *, domain, api_key, timeout=10.0):
        return FreshserviceDepartment(
            freshservice_id=freshservice_id, name="Sample Organization", domains=["sample.example.test", "new.example.test"]
        )

    monkeypatch.setattr("app.services.departments.fetch_department", _updated_fetch)
    refresh_department(
        db_session, department_id=dept.id, actor_user_id=actor_id, settings=get_settings()
    )

    entry = (
        db_session.query(AuditLog)
        .filter_by(target_type="department", target_id=str(dept.id), action_type="department.refresh")
        .one()
    )
    assert entry.user_id == actor_id
    assert entry.before_value == {"name": "Sample Organization", "domains": ["sample.example.test", "support.example.test"]}
    assert entry.after_value == {"name": "Sample Organization", "domains": ["sample.example.test", "new.example.test"]}


def test_audit_entry_atomic_with_failed_mutation(db_session):
    """The audit foundation's core guarantee: record() writes inside the
    caller's transaction, so a mutation that fails after record() was called
    leaves no orphaned audit entry behind."""
    actor_id = _make_user(db_session)
    dept = Department(freshservice_id="atomic-1", name="Temp", domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()

    audit.record(
        db_session,
        user_id=actor_id,
        action_type="department.create",
        target_type="department",
        target_id=str(dept.id),
        before_value=None,
        after_value={"name": "Temp"},
    )

    # Force the surrounding mutation to fail before it ever commits.
    db_session.add(Department(freshservice_id=None, name="bad", domains=[], deleted=False))
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    assert db_session.query(Department).count() == 0
    assert db_session.query(AuditLog).count() == 0


# ── API layer — admin gate ───────────────────────────────────────────────────


def test_non_admin_refused_by_mutating_endpoints(db_session, monkeypatch, sign_in_as):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)
    client = sign_in_as(email=VIEWER_EMAIL)

    assert client.post("/api/departments", json={"freshservice_id": "1"}).status_code == 403
    assert client.post("/api/departments/1/delete").status_code == 403
    assert client.post("/api/departments/1/refresh").status_code == 403


def test_non_admin_reads_only_granted_departments(db_session, monkeypatch, sign_in_as):
    """GET is readable by any signed-in user but scoped. Without this a
    non-admin can only ever see
    raw department ids, and no department-scoped screen can name what it shows.
    """
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)

    granted = Department(freshservice_id="10", name="Granted", domains=[], deleted=False)
    hidden = Department(freshservice_id="11", name="Hidden", domains=[], deleted=False)
    db_session.add_all([granted, hidden])
    db_session.flush()

    client = sign_in_as(email=VIEWER_EMAIL)
    viewer = db_session.query(User).filter(User.email == VIEWER_EMAIL).one()
    db_session.add(
        UserDepartmentRole(user_id=viewer.id, department_id=granted.id, role=Role.viewer)
    )
    db_session.commit()

    response = client.get("/api/departments")
    assert response.status_code == 200
    assert [d["name"] for d in response.json()] == ["Granted"]


def test_admin_reads_every_department(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    db_session.add_all(
        [
            Department(freshservice_id="10", name="One", domains=[], deleted=False),
            Department(freshservice_id="11", name="Two", domains=[], deleted=False),
        ]
    )
    db_session.commit()

    client = sign_in_as(email=ADMIN_EMAIL)
    response = client.get("/api/departments")
    assert response.status_code == 200
    assert [d["name"] for d in response.json()] == ["One", "Two"]


def test_admin_can_add_department_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/departments", json={"freshservice_id": "77"})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Sample Organization"
    assert body["domains"] == ["sample.example.test", "support.example.test"]


def test_unrecognised_identifier_returns_404_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)

    def _not_found(freshservice_id, *, domain, api_key, timeout=10.0):
        raise FreshserviceNotFoundError(freshservice_id)

    monkeypatch.setattr("app.services.departments.fetch_department", _not_found)
    client = sign_in_as(email=ADMIN_EMAIL)

    response = client.post("/api/departments", json={"freshservice_id": "999"})
    assert response.status_code == 404
    assert db_session.query(Department).count() == 0


def test_admin_can_refresh_department_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    client = sign_in_as(email=ADMIN_EMAIL)
    created = client.post("/api/departments", json={"freshservice_id": "77"}).json()

    def _updated_fetch(freshservice_id, *, domain, api_key, timeout=10.0):
        return FreshserviceDepartment(
            freshservice_id=freshservice_id, name="Sample Organization", domains=["sample.example.test", "hr.example.test"]
        )

    monkeypatch.setattr("app.services.departments.fetch_department", _updated_fetch)
    response = client.post(f"/api/departments/{created['id']}/refresh")

    assert response.status_code == 200
    assert response.json()["domains"] == ["sample.example.test", "hr.example.test"]


def test_viewing_departments_produces_no_audit_entries(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    monkeypatch.setattr("app.services.departments.fetch_department", _fake_fetch)
    client = sign_in_as(email=ADMIN_EMAIL)
    client.post("/api/departments", json={"freshservice_id": "42"})

    before = db_session.query(AuditLog).count()
    response = client.get("/api/departments")
    assert response.status_code == 200
    assert db_session.query(AuditLog).count() == before
