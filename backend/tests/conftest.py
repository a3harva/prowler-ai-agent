"""Shared fixtures for the backend test suite.

Tests run against a real Postgres (TEST_DATABASE_URL) — the schema uses JSONB
and ARRAY columns, so SQLite is not a substitute. No fixture here connects
eagerly; connections happen lazily inside tests that request db_session, so an
empty test suite collects and passes without touching the database.
"""

import pytest
from _pytest.config import ExitCode
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.api.main import app
from app.config import get_settings
from app.db import get_db
from app.models import Base


def pytest_sessionfinish(session, exitstatus):
    # An empty suite is the expected state before Phase 1 adds real tests —
    # "no tests collected" should not read as a failed run.
    if exitstatus == ExitCode.NO_TESTS_COLLECTED:
        session.exitstatus = ExitCode.OK


@pytest.fixture(autouse=True)
def _no_tracing_in_tests():
    """The suite never emits telemetry, whatever local configuration says.

    Test isolation must prevent fixture activity from reaching an enabled
    collector. A function-scoped reset is required because observability tests
    may reset module state after an earlier test. Re-asserting the disabled
    state before every test prevents a later test from resolving a configured
    client unexpectedly.

    `tests/test_observability.py` is unaffected: its own autouse fixture is
    module-level, so it runs after this one and still resolves whatever client
    each of its tests needs.
    """
    from app import observability

    observability.reset_for_tests()
    observability._resolved = True
    observability._client = None
    yield
    observability.reset_for_tests()


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(get_settings().test_database_url, pool_pre_ping=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    """One test = one outer transaction, rolled back at teardown, with a
    SAVEPOINT restarted after every commit so code under test (e.g.
    services/users.py calling db.commit()) can commit freely without the
    change surviving past the test."""
    connection = db_engine.connect()
    outer_transaction = connection.begin()
    session = sessionmaker(bind=connection)()

    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        nonlocal nested
        if not nested.is_active:
            nested = connection.begin_nested()

    try:
        yield session
    finally:
        session.close()
        outer_transaction.rollback()
        connection.close()


@pytest.fixture()
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def sign_in_as(client, monkeypatch):
    """Drives the real Google OAuth callback with the network calls stubbed
    out, so a signed-in session is a real session (real user row, real
    cookies) rather than a bypass of the auth path under test elsewhere."""

    def _sign_in(*, email: str, name: str = "Test User"):
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
        callback = client.get(
            f"/api/auth/callback?code=fake&state={state_cookie}", follow_redirects=False
        )
        assert "access_token" in callback.cookies
        return client

    return _sign_in


@pytest.fixture()
def sign_in_with_password(client, db_session):
    """Drives the real password login endpoint — nothing stubbed, unlike
    sign_in_as. Lets tests create multiple distinct identities without
    needing separate real Google accounts, for RBAC scenarios."""
    from app.services.users import get_or_create_user_by_email, set_user_password

    def _sign_in(*, email: str, password: str, name: str = "Test User"):
        provisional = get_or_create_user_by_email(db_session, email=email)
        db_session.commit()
        user = set_user_password(
            db_session, email=email, new_password=password, actor_user_id=provisional.id
        )
        user.name = name
        db_session.commit()
        response = client.post("/api/auth/login-local", json={"email": email, "password": password})
        assert "access_token" in response.cookies
        return client

    return _sign_in
