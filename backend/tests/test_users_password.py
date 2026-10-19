import uuid

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.users import get_or_create_user_by_email, set_user_password

ADMIN_EMAIL = "admin@example.test"


def _unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.test"


def _as_admin(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", ADMIN_EMAIL)


def _make_actor(db_session) -> int:
    actor = User(email=_unique_email("actor"), name="Actor")
    db_session.add(actor)
    db_session.flush()
    return actor.id


# ── service layer ────────────────────────────────────────────────────────────


def test_set_user_password_auto_provisions_user(db_session):
    email = _unique_email("provision")
    actor_id = _make_actor(db_session)

    user = set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=actor_id)

    assert user.email == email
    assert user.password_hash is not None


def test_set_user_password_reuses_existing_user(db_session):
    email = _unique_email("existing")
    actor_id = _make_actor(db_session)
    existing = get_or_create_user_by_email(db_session, email=email)
    db_session.commit()
    existing_id = existing.id

    user = set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=actor_id)

    assert user.id == existing_id
    assert db_session.query(User).filter_by(email=email).count() == 1


def test_reset_password_invalidates_old_password(db_session):
    from app.auth.passwords import verify_password

    email = _unique_email("reset")
    actor_id = _make_actor(db_session)
    set_user_password(db_session, email=email, new_password="first-password-123", actor_user_id=actor_id)
    user = set_user_password(db_session, email=email, new_password="second-password-456", actor_user_id=actor_id)

    assert not verify_password("first-password-123", user.password_hash)
    assert verify_password("second-password-456", user.password_hash)


def test_set_password_creates_audit_entry_without_leaking_credential(db_session):
    email = _unique_email("audited")
    actor_id = _make_actor(db_session)

    user = set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=actor_id)

    entry = db_session.query(AuditLog).filter_by(target_type="user", target_id=str(user.id)).one()
    assert entry.action_type == "user.set_password"
    assert entry.before_value == {"had_password": False}
    assert entry.after_value == {"had_password": True}
    assert "a-real-password-123" not in str(entry.before_value) + str(entry.after_value)
    assert user.password_hash not in str(entry.before_value) + str(entry.after_value)


# ── API layer ────────────────────────────────────────────────────────────────


def test_non_admin_refused_setting_password(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    client = sign_in_as(email="viewer@example.test")

    response = client.post("/api/users/password", json={"email": _unique_email("x"), "password": "a-real-password-123"})
    assert response.status_code == 403


def test_admin_sets_password_and_new_user_can_log_in(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    email = _unique_email("newlogin")

    response = admin_client.post("/api/users/password", json={"email": email, "password": "a-real-password-123"})
    assert response.status_code == 200
    assert response.json()["has_password"] is True

    admin_client.post("/api/auth/logout")
    admin_client.cookies.clear()

    login_response = admin_client.post(
        "/api/auth/login-local", json={"email": email, "password": "a-real-password-123"}
    )
    assert login_response.status_code == 200


def test_users_listing_reports_has_password(db_session, monkeypatch, sign_in_as):
    _as_admin(monkeypatch)
    admin_client = sign_in_as(email=ADMIN_EMAIL)
    email = _unique_email("listed")
    admin_client.post("/api/users/password", json={"email": email, "password": "a-real-password-123"})

    listing = admin_client.get("/api/users").json()
    matched = next(u for u in listing if u["email"] == email)
    assert matched["has_password"] is True

    admin_row = next(u for u in listing if u["email"] == ADMIN_EMAIL)
    assert admin_row["has_password"] is False
