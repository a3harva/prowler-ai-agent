import datetime

import jwt
import pytest

from app.api.deps import ACCESS_COOKIE_NAME, bootstrap_admin_emails
from app.auth.domain_gate import DomainNotAllowedError, check_hosted_domain
from app.auth.tokens import ALGORITHM, TokenError, create_access_token, create_refresh_token, decode_token
from app.config import get_settings
from app.models.department import Department
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.users import upsert_user_from_login


# ── domain gate — pure, no network ──────────────────────────────────────────


def test_domain_gate_accepts_matching_claim():
    check_hosted_domain({"hd": "example.test", "email": "a@example.test"}, allowed_domain="example.test")


def test_domain_gate_rejects_personal_account():
    with pytest.raises(DomainNotAllowedError):
        check_hosted_domain({"email": "a@outside.example.test"}, allowed_domain="example.test")


def test_forged_login_hint_does_not_grant_access():
    # The /login endpoint's `hd=` hint is never consulted here — only the
    # verified claims from the ID token are. A claims dict with no `hd` (as a
    # personal Google account produces) is rejected regardless of any hint
    # that was sent on the original authorization request.
    claims_from_personal_account = {"email": "attacker@outside.example.test", "email_verified": True}
    with pytest.raises(DomainNotAllowedError):
        check_hosted_domain(claims_from_personal_account, allowed_domain="example.test")


# ── users upsert — single write path ────────────────────────────────────────


def test_first_login_creates_user(db_session):
    user = upsert_user_from_login(db_session, email="new@example.test", name="New Person")
    assert user.id is not None
    assert user.last_login_at is not None

    count = db_session.query(User).filter_by(email="new@example.test").count()
    assert count == 1


def test_second_login_updates_not_duplicates(db_session):
    first = upsert_user_from_login(db_session, email="repeat@example.test", name="First Name")
    second = upsert_user_from_login(db_session, email="repeat@example.test", name="Updated Name")

    assert first.id == second.id
    assert second.name == "Updated Name"
    count = db_session.query(User).filter_by(email="repeat@example.test").count()
    assert count == 1


# ── tokens ───────────────────────────────────────────────────────────────────


def test_access_token_roundtrip():
    settings = get_settings()
    token = create_access_token(user_id=1, email="a@example.test", settings=settings)
    payload = decode_token(token, expected_type="access", settings=settings)
    assert payload["sub"] == "1"
    assert payload["email"] == "a@example.test"


def test_refresh_token_rejected_as_access_token():
    settings = get_settings()
    token = create_refresh_token(user_id=1, settings=settings)
    with pytest.raises(TokenError):
        decode_token(token, expected_type="access", settings=settings)


def test_expired_access_token_rejected():
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = jwt.encode(
        {"sub": "1", "email": "a@example.test", "type": "access", "iat": now - datetime.timedelta(hours=1), "exp": now - datetime.timedelta(minutes=1)},
        settings["JWT_SIGNING_KEY"],
        algorithm=ALGORITHM,
    )
    with pytest.raises(TokenError):
        decode_token(expired, expected_type="access", settings=settings)


# ── bootstrap admin ──────────────────────────────────────────────────────────


def test_bootstrap_admin_emails_parsed(monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", "a@example.test, B@example.test")
    emails = bootstrap_admin_emails(settings)
    assert emails == {"a@example.test", "b@example.test"}


# ── endpoints ────────────────────────────────────────────────────────────────


def test_protected_endpoint_refuses_unauthenticated(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_me_reports_per_department_grants(db_session, monkeypatch, sign_in_as):
    """The interface hides controls a Viewer cannot use, which is only
    possible if /auth/me says what the user's role is per department. A
    global-admin boolean alone cannot distinguish Editor from Viewer.
    """
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", "admin@example.test")

    editor_dept = Department(freshservice_id="20", name="Editable", domains=[], deleted=False)
    viewer_dept = Department(freshservice_id="21", name="Readable", domains=[], deleted=False)
    db_session.add_all([editor_dept, viewer_dept])
    db_session.flush()

    client = sign_in_as(email="engineer@example.test")
    user = db_session.query(User).filter(User.email == "engineer@example.test").one()
    db_session.add_all(
        [
            UserDepartmentRole(user_id=user.id, department_id=editor_dept.id, role=Role.editor),
            UserDepartmentRole(user_id=user.id, department_id=viewer_dept.id, role=Role.viewer),
        ]
    )
    db_session.commit()

    body = client.get("/api/auth/me").json()
    assert body["is_bootstrap_admin"] is False
    assert {(g["department_id"], g["role"]) for g in body["grants"]} == {
        (editor_dept.id, "editor"),
        (viewer_dept.id, "viewer"),
    }


def test_me_reports_no_grants_for_bootstrap_admin_without_rows(db_session, monkeypatch, sign_in_as):
    """A global admin needs no per-department rows — `grants` is legitimately
    empty and the interface must treat is_bootstrap_admin as additive rather
    than inferring "no access" from an empty list.
    """
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", "admin@example.test")
    client = sign_in_as(email="admin@example.test")

    body = client.get("/api/auth/me").json()
    assert body["is_bootstrap_admin"] is True
    assert body["grants"] == []


def test_callback_wrong_domain_creates_no_user_and_sets_no_session(client, monkeypatch, db_session):
    monkeypatch.setattr(
        "app.api.routers.auth.exchange_code_for_id_token", lambda **kwargs: "fake-id-token"
    )
    monkeypatch.setattr(
        "app.api.routers.auth.verify_id_token",
        lambda *args, **kwargs: {"email": "attacker@outside.example.test", "email_verified": True},
    )

    login_response = client.get("/api/auth/login", follow_redirects=False)
    state_cookie = login_response.cookies.get("oauth_state")

    response = client.get(
        f"/api/auth/callback?code=fake&state={state_cookie}",
        follow_redirects=False,
    )

    assert response.status_code in (302, 307)
    assert ACCESS_COOKIE_NAME not in response.cookies
    assert db_session.query(User).filter_by(email="attacker@outside.example.test").count() == 0


def test_callback_valid_domain_creates_user_and_sets_session(client, monkeypatch, db_session):
    monkeypatch.setattr(
        "app.api.routers.auth.exchange_code_for_id_token", lambda **kwargs: "fake-id-token"
    )
    monkeypatch.setattr(
        "app.api.routers.auth.verify_id_token",
        lambda *args, **kwargs: {
            "email": "engineer@example.test",
            "email_verified": True,
            "hd": "example.test",
            "name": "Engineer",
        },
    )

    login_response = client.get("/api/auth/login", follow_redirects=False)
    state_cookie = login_response.cookies.get("oauth_state")

    response = client.get(
        f"/api/auth/callback?code=fake&state={state_cookie}",
        follow_redirects=False,
    )

    assert response.status_code in (302, 307)
    assert ACCESS_COOKIE_NAME in response.cookies
    assert db_session.query(User).filter_by(email="engineer@example.test").count() == 1


def _sign_in(client, monkeypatch, *, email: str, name: str = "Engineer"):
    monkeypatch.setattr(
        "app.api.routers.auth.exchange_code_for_id_token", lambda **kwargs: "fake-id-token"
    )
    monkeypatch.setattr(
        "app.api.routers.auth.verify_id_token",
        lambda *args, **kwargs: {
            "email": email,
            "email_verified": True,
            "hd": "example.test",
            "name": name,
        },
    )
    login_response = client.get("/api/auth/login", follow_redirects=False)
    state_cookie = login_response.cookies.get("oauth_state")
    return client.get(f"/api/auth/callback?code=fake&state={state_cookie}", follow_redirects=False)


def test_session_survives_reload(client, monkeypatch):
    _sign_in(client, monkeypatch, email="reload@example.test")

    # A fresh request using only the stored cookie jar — standing in for a
    # page reload, which re-fetches /auth/me with no other state.
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "reload@example.test"


def test_expired_access_token_is_renewed_via_refresh(client, monkeypatch):
    _sign_in(client, monkeypatch, email="renew@example.test")

    settings = get_settings()
    live_payload = decode_token(
        client.cookies.get(ACCESS_COOKIE_NAME), expected_type="access", settings=settings
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_access = jwt.encode(
        {
            "sub": live_payload["sub"],
            "email": "renew@example.test",
            "type": "access",
            "iat": now - datetime.timedelta(hours=1),
            "exp": now - datetime.timedelta(minutes=1),
        },
        settings["JWT_SIGNING_KEY"],
        algorithm=ALGORITHM,
    )
    client.cookies.set(ACCESS_COOKIE_NAME, expired_access)

    # /auth/me itself would 401 on the expired token — the refresh endpoint is
    # what the frontend's axios interceptor calls transparently on that 401.
    assert client.get("/api/auth/me").status_code == 401

    refresh_response = client.post("/api/auth/refresh")
    assert refresh_response.status_code == 200
    assert ACCESS_COOKIE_NAME in refresh_response.cookies

    client.cookies.set(ACCESS_COOKIE_NAME, refresh_response.cookies.get(ACCESS_COOKIE_NAME))
    assert client.get("/api/auth/me").status_code == 200


def test_logout_clears_session_and_blocks_protected_routes(client, monkeypatch):
    _sign_in(client, monkeypatch, email="logout@example.test")
    assert client.get("/api/auth/me").status_code == 200

    logout_response = client.post("/api/auth/logout")
    assert logout_response.status_code == 200

    client.cookies.clear()
    assert client.get("/api/auth/me").status_code == 401


def test_bootstrap_admin_flagged_on_first_login(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", "boss@example.test")

    _sign_in(client, monkeypatch, email="boss@example.test")

    response = client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["is_bootstrap_admin"] is True


def test_non_bootstrap_user_not_flagged_admin(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", "boss@example.test")

    _sign_in(client, monkeypatch, email="regular@example.test")

    response = client.get("/api/auth/me")
    assert response.json()["is_bootstrap_admin"] is False
