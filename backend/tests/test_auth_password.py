import uuid

import pytest

from app.api.deps import ACCESS_COOKIE_NAME
from app.auth.domain_gate import is_email_domain_allowed
from app.auth.passwords import (
    PasswordTooLongError,
    PasswordTooShortError,
    hash_password,
    verify_password,
)
from app.config import get_settings
from app.models.user import User
from app.services.users import set_user_password


def _unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.test"


def _make_actor(db_session) -> int:
    actor = User(email=_unique_email("actor"), name="Actor")
    db_session.add(actor)
    db_session.flush()
    return actor.id


# ── password hashing — pure, no network ─────────────────────────────────────


def test_hash_and_verify_roundtrip():
    hashed = hash_password("correct-horse-battery")
    assert verify_password("correct-horse-battery", hashed)
    assert not verify_password("wrong-password", hashed)


def test_password_too_short_rejected():
    with pytest.raises(PasswordTooShortError):
        hash_password("short")


def test_password_too_long_rejected():
    with pytest.raises(PasswordTooLongError):
        hash_password("x" * 73)


def test_domain_suffix_check():
    assert is_email_domain_allowed("a@example.test", allowed_domain="example.test")
    assert not is_email_domain_allowed("a@outside.example.test", allowed_domain="example.test")


# ── login-local endpoint ─────────────────────────────────────────────────────


def test_login_local_success_sets_session_cookies(client, db_session):
    email = _unique_email("login-ok")
    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()

    response = client.post("/api/auth/login-local", json={"email": email, "password": "a-real-password-123"})
    assert response.status_code == 200
    assert ACCESS_COOKIE_NAME in response.cookies


def test_login_local_wrong_password_rejected(client, db_session):
    email = _unique_email("login-wrong")
    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()

    response = client.post("/api/auth/login-local", json={"email": email, "password": "not-the-password"})
    assert response.status_code == 401
    assert ACCESS_COOKIE_NAME not in response.cookies


def test_login_local_unknown_user_rejected(client):
    response = client.post(
        "/api/auth/login-local", json={"email": _unique_email("nope"), "password": "whatever-1234"}
    )
    assert response.status_code == 401


def test_login_local_no_password_set_rejected(client, db_session):
    email = _unique_email("nopass")
    db_session.add(User(email=email, name="No Password"))
    db_session.commit()

    response = client.post("/api/auth/login-local", json={"email": email, "password": "whatever-1234"})
    assert response.status_code == 401


def test_login_local_wrong_domain_rejected(client, db_session, monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "ALLOWED_EMAIL_DOMAIN", "example.test")
    email = f"outsider-{uuid.uuid4().hex[:8]}@outside.example.test"
    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()

    response = client.post("/api/auth/login-local", json={"email": email, "password": "a-real-password-123"})
    assert response.status_code == 403


def test_login_local_rate_limited_after_repeated_failures(client, db_session):
    email = _unique_email("throttle")
    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()

    for _ in range(5):
        response = client.post("/api/auth/login-local", json={"email": email, "password": "wrong"})
        assert response.status_code == 401

    response = client.post("/api/auth/login-local", json={"email": email, "password": "wrong"})
    assert response.status_code == 429


def test_login_local_session_matches_google_session_shape(client, db_session, sign_in_with_password):
    email = _unique_email("shape")
    password_client = sign_in_with_password(email=email, password="a-real-password-123")
    me_response = password_client.get("/api/auth/me")
    assert me_response.status_code == 200
    assert me_response.json()["email"] == email


# ── password/Google upsert interaction (regression) ─────────────────────────


def test_google_login_after_password_account_preserves_password(client, monkeypatch, db_session):
    """A password account's hash must survive a later real Google sign-in for
    the same email — upsert_user_from_login's set_ dict must never touch
    password_hash."""
    email = _unique_email("preserve-hash")
    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()
    original_hash = db_session.query(User).filter_by(email=email).one().password_hash

    monkeypatch.setattr("app.api.routers.auth.exchange_code_for_id_token", lambda **kwargs: "fake-id-token")
    monkeypatch.setattr(
        "app.api.routers.auth.verify_id_token",
        lambda *args, **kwargs: {"email": email, "email_verified": True, "hd": "example.test", "name": "Google Name"},
    )
    login_response = client.get("/api/auth/login", follow_redirects=False)
    state_cookie = login_response.cookies.get("oauth_state")
    client.get(f"/api/auth/callback?code=fake&state={state_cookie}", follow_redirects=False)

    db_session.expire_all()
    updated = db_session.query(User).filter_by(email=email).one()
    assert updated.password_hash == original_hash
    assert updated.name == "Google Name"


def test_admin_set_password_after_google_login_preserves_name(client, monkeypatch, db_session):
    """The reverse: setting a password for a Google-first user must not touch
    the name a later Google login would otherwise refresh."""
    email = _unique_email("preserve-name")
    monkeypatch.setattr("app.api.routers.auth.exchange_code_for_id_token", lambda **kwargs: "fake-id-token")
    monkeypatch.setattr(
        "app.api.routers.auth.verify_id_token",
        lambda *args, **kwargs: {"email": email, "email_verified": True, "hd": "example.test", "name": "Google Name"},
    )
    login_response = client.get("/api/auth/login", follow_redirects=False)
    state_cookie = login_response.cookies.get("oauth_state")
    client.get(f"/api/auth/callback?code=fake&state={state_cookie}", follow_redirects=False)

    set_user_password(db_session, email=email, new_password="a-real-password-123", actor_user_id=_make_actor(db_session))
    db_session.commit()

    db_session.expire_all()
    updated = db_session.query(User).filter_by(email=email).one()
    assert updated.name == "Google Name"
    assert updated.password_hash is not None
