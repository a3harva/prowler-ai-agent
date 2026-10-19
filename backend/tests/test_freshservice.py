import requests

from app.integrations import freshservice


class _FakeResponse:
    def __init__(self, *, status_code, payload=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._payload = payload

    def json(self):
        return self._payload


def test_fetch_department_success(monkeypatch):
    def _fake_get(url, auth, timeout):
        assert url.endswith("/api/v2/departments/42")
        assert auth == ("key123", "X")
        return _FakeResponse(
            status_code=200,
            payload={"department": {"id": 42, "name": "Sample Organization", "domains": ["sample.example.test"]}},
        )

    monkeypatch.setattr(freshservice.requests, "get", _fake_get)

    dept = freshservice.fetch_department("42", domain="sample.example.test", api_key="key123")
    assert dept.freshservice_id == "42"
    assert dept.name == "Sample Organization"
    assert dept.domains == ["sample.example.test"]


def test_fetch_department_not_found(monkeypatch):
    monkeypatch.setattr(
        freshservice.requests, "get", lambda url, auth, timeout: _FakeResponse(status_code=404)
    )

    try:
        freshservice.fetch_department("999", domain="sample.example.test", api_key="key123")
        assert False, "expected FreshserviceNotFoundError"
    except freshservice.FreshserviceNotFoundError:
        pass


def test_fetch_department_server_error(monkeypatch):
    monkeypatch.setattr(
        freshservice.requests, "get", lambda url, auth, timeout: _FakeResponse(status_code=500)
    )

    try:
        freshservice.fetch_department("42", domain="sample.example.test", api_key="key123")
        assert False, "expected FreshserviceUnavailableError"
    except freshservice.FreshserviceUnavailableError:
        pass


def test_fetch_department_network_failure(monkeypatch):
    def _raise(url, auth, timeout):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(freshservice.requests, "get", _raise)

    try:
        freshservice.fetch_department("42", domain="sample.example.test", api_key="key123")
        assert False, "expected FreshserviceUnavailableError"
    except freshservice.FreshserviceUnavailableError:
        pass
