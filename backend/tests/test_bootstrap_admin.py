import uuid

import pytest

from app.auth.passwords import PasswordTooShortError, verify_password
from app.bootstrap_admin import NotBootstrapAdminError, set_bootstrap_admin_password
from app.config import get_settings
from app.models.audit_log import AuditLog


def _admin_settings(monkeypatch) -> tuple[str, object]:
    email = f"admin-{uuid.uuid4().hex[:8]}@example.test"
    settings = get_settings()
    monkeypatch.setitem(settings.values, "BOOTSTRAP_ADMIN_EMAILS", email)
    return email, settings


def test_sets_password_for_bootstrap_admin(db_session, monkeypatch):
    email, settings = _admin_settings(monkeypatch)

    user = set_bootstrap_admin_password(
        db_session, email=email.upper(), password="a-real-password-123", settings=settings
    )

    assert user.email == email
    assert verify_password("a-real-password-123", user.password_hash)


def test_records_admin_as_its_own_actor(db_session, monkeypatch):
    email, settings = _admin_settings(monkeypatch)

    user = set_bootstrap_admin_password(db_session, email=email, password="a-real-password-123", settings=settings)

    entry = db_session.query(AuditLog).filter_by(target_type="user", target_id=str(user.id)).one()
    assert entry.user_id == user.id
    assert entry.action_type == "user.set_password"


def test_refuses_address_outside_bootstrap_list(db_session, monkeypatch):
    _email, settings = _admin_settings(monkeypatch)

    with pytest.raises(NotBootstrapAdminError):
        set_bootstrap_admin_password(
            db_session, email="someone-else@example.test", password="a-real-password-123", settings=settings
        )


def test_enforces_password_policy(db_session, monkeypatch):
    email, settings = _admin_settings(monkeypatch)

    with pytest.raises(PasswordTooShortError):
        set_bootstrap_admin_password(db_session, email=email, password="short", settings=settings)
