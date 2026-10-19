"""The audit trail's viewing screen. Writing entries is exercised by every
other test file that calls `audit.record` alongside its own mutation
(test_departments.py, test_users.py, test_organizations.py, ...) — this
file is only about reading them back: filtering, combination, and the
read-path itself never producing an entry.
"""

import datetime

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import audit

ADMIN_EMAIL = "admin@example.test"
VIEWER_EMAIL = "viewer@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_user(db_session, email="actor@example.test") -> User:
    user = User(email=email, name=email.split("@")[0].title())
    db_session.add(user)
    db_session.flush()
    return user


def _record(db_session, *, user_id, action_type="department.create", target_type="department", target_id="1"):
    entry = audit.record(
        db_session, user_id=user_id, action_type=action_type, target_type=target_type,
        target_id=target_id, before_value=None, after_value={"name": "New Dept"},
    )
    db_session.commit()
    return entry


# ── service layer ────────────────────────────────────────────────────────────


def test_list_audit_log_returns_actor_identity_without_a_second_lookup(db_session):
    user = _make_user(db_session)
    _record(db_session, user_id=user.id)

    rows = audit.list_audit_log(db_session)

    assert len(rows) == 1
    entry, actor_email, actor_name = rows[0]
    assert actor_email == user.email
    assert actor_name == user.name


def test_list_audit_log_orders_most_recent_first(db_session):
    user = _make_user(db_session)
    first = _record(db_session, user_id=user.id, target_id="1")
    second = _record(db_session, user_id=user.id, target_id="2")

    rows = audit.list_audit_log(db_session)

    assert [entry.id for entry, _, _ in rows] == [second.id, first.id]


def test_filter_by_user(db_session):
    user_a = _make_user(db_session, "a@example.test")
    user_b = _make_user(db_session, "b@example.test")
    _record(db_session, user_id=user_a.id)
    _record(db_session, user_id=user_b.id)

    rows = audit.list_audit_log(db_session, user_id=user_a.id)

    assert len(rows) == 1
    assert rows[0][1] == "a@example.test"


def test_filter_by_action_type(db_session):
    user = _make_user(db_session)
    _record(db_session, user_id=user.id, action_type="department.create")
    _record(db_session, user_id=user.id, action_type="department.delete")

    rows = audit.list_audit_log(db_session, action_type="department.delete")

    assert len(rows) == 1
    assert rows[0][0].action_type == "department.delete"


def test_filter_by_target_type(db_session):
    user = _make_user(db_session)
    _record(db_session, user_id=user.id, target_type="department")
    _record(db_session, user_id=user.id, target_type="project")

    rows = audit.list_audit_log(db_session, target_type="project")

    assert len(rows) == 1
    assert rows[0][0].target_type == "project"


def test_filter_by_date_range(db_session):
    user = _make_user(db_session)
    entry = _record(db_session, user_id=user.id)
    # Backdate one entry outside the window under test — direct column
    # update, since `record()` always stamps "now".
    db_session.execute(
        AuditLog.__table__.update().where(AuditLog.id == entry.id).values(
            timestamp=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        )
    )
    db_session.commit()
    _record(db_session, user_id=user.id, target_id="2")

    recent_only = audit.list_audit_log(
        db_session, date_from=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    )

    assert len(recent_only) == 1
    assert recent_only[0][0].target_id == "2"


def test_filters_combine_with_and(db_session):
    user_a = _make_user(db_session, "a@example.test")
    user_b = _make_user(db_session, "b@example.test")
    _record(db_session, user_id=user_a.id, action_type="department.create")
    _record(db_session, user_id=user_a.id, action_type="department.delete")
    _record(db_session, user_id=user_b.id, action_type="department.create")

    rows = audit.list_audit_log(db_session, user_id=user_a.id, action_type="department.create")

    assert len(rows) == 1
    entry, actor_email, _ = rows[0]
    assert actor_email == "a@example.test"
    assert entry.action_type == "department.create"


# ── API layer ────────────────────────────────────────────────────────────────


def test_admin_views_audit_log_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    admin_user = db_session.query(User).filter_by(email=ADMIN_EMAIL).one()
    _record(db_session, user_id=admin_user.id)

    response = admin_client.get("/api/audit")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["actor_email"] == ADMIN_EMAIL
    assert body[0]["action_type"] == "department.create"
    assert body[0]["after_value"] == {"name": "New Dept"}


def test_non_admin_cannot_view_audit_log_via_endpoint(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    sign_in_as(email=ADMIN_EMAIL)

    viewer = User(email=VIEWER_EMAIL, name="Viewer")
    db_session.add(viewer)
    db_session.commit()

    client = sign_in_as(email=VIEWER_EMAIL)
    response = client.get("/api/audit")
    assert response.status_code == 403


def test_audit_log_endpoint_refused_without_signing_in(client):
    response = client.get("/api/audit")
    assert response.status_code == 401


def test_admin_filters_audit_log_via_endpoint_query_params(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    admin_user = db_session.query(User).filter_by(email=ADMIN_EMAIL).one()
    _record(db_session, user_id=admin_user.id, action_type="department.create")
    _record(db_session, user_id=admin_user.id, action_type="department.delete")

    response = admin_client.get("/api/audit?action_type=department.delete")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["action_type"] == "department.delete"


def test_viewing_the_audit_log_itself_produces_no_entry(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin_client = sign_in_as(email=ADMIN_EMAIL)

    before = db_session.query(AuditLog).count()
    admin_client.get("/api/audit")
    after = db_session.query(AuditLog).count()

    assert after == before
