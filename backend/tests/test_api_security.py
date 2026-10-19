"""Unit tests for the transport-level security controls.

These build a throwaway Starlette app rather than importing ``app.api.main``,
so they run anywhere the Starlette/FastAPI packages are importable and do not
need PostgreSQL, Redis, or the WeasyPrint native libraries.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.security import SecurityMiddleware, install_security_middleware, security_headers


def _app(*, tls: bool, origins: tuple[str, ...] = ()) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, tls=tls, allowed_origins=list(origins))

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mutate")
    def mutate() -> dict[str, str]:
        return {"status": "ok"}

    return app


def test_standard_headers_are_present_even_without_tls():
    client = TestClient(_app(tls=False))
    response = client.get("/ping")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "content-security-policy" not in response.headers
    assert "strict-transport-security" not in response.headers


def test_csp_and_hsts_only_on_tls():
    client = TestClient(_app(tls=True))
    response = client.get("/ping")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["strict-transport-security"].startswith("max-age=")


def test_oversized_body_is_rejected_before_the_handler():
    client = TestClient(_app(tls=False))
    response = client.post("/mutate", content=b"x" * (11 * 1024 * 1024))
    assert response.status_code == 413


def test_cross_origin_mutation_is_rejected():
    client = TestClient(_app(tls=False, origins=("https://console.example.test",)))
    response = client.post("/mutate", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_same_host_mutation_is_allowed():
    client = TestClient(_app(tls=False, origins=("https://console.example.test",)))
    response = client.post("/mutate", headers={"Origin": "https://testserver"})
    assert response.status_code == 200


def test_configured_frontend_origin_is_allowed():
    client = TestClient(_app(tls=False, origins=("https://console.example.test",)))
    response = client.post("/mutate", headers={"Origin": "https://console.example.test"})
    assert response.status_code == 200


def test_non_browser_client_without_origin_is_allowed():
    client = TestClient(_app(tls=False, origins=("https://console.example.test",)))
    response = client.post("/mutate")
    assert response.status_code == 200


def test_trusted_host_rejects_unknown_host():
    app = FastAPI()
    install_security_middleware(app, tls=True, allowed_hosts=["console.example.test"])

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    client = TestClient(app, base_url="http://attacker.example")
    assert client.get("/ping").status_code == 400


def test_security_headers_helper_shape():
    assert "Strict-Transport-Security" in security_headers(tls=True)
    assert "Content-Security-Policy" not in security_headers(tls=False)