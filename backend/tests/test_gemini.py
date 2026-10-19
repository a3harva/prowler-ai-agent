"""Unit tests for the Vertex AI client.

The request builders are pure, so everything except the credential test runs
without a network. The credential test is the one that matters most: the whole
reason this feature impersonates a service account is so no Vertex call is ever
made as a human, and that is worth an assertion rather than an eyeball.
"""

import pytest

from app.integrations.gemini import (
    GeminiError,
    _call_once,
    build_endpoint,
    build_payload,
    resolved_principal,
)


def test_global_location_uses_the_bare_host():
    """`global` is not a regional prefix. Getting this wrong returns a 404 that
    reads like a missing model rather than a wrong URL — which is exactly how
    it presented during exploration."""
    url = build_endpoint(project_id="p", location="global", model="gemini-2.5-pro")
    assert url.startswith("https://aiplatform.googleapis.com/v1/projects/p/locations/global/")
    assert "global-aiplatform" not in url


def test_regional_location_is_prefixed():
    url = build_endpoint(project_id="p", location="us-central1", model="gemini-2.5-pro")
    assert url.startswith("https://us-central1-aiplatform.googleapis.com/")


def test_payload_requests_structured_json():
    payload = build_payload(
        system_instruction="sys",
        user_content="user",
        response_schema={"type": "OBJECT"},
        max_output_tokens=1234,
    )
    config = payload["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"] == {"type": "OBJECT"}
    assert config["maxOutputTokens"] == 1234
    assert payload["systemInstruction"]["parts"][0]["text"] == "sys"


class _FakeResponse:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body or {}
        self.text = text

    def json(self):
        return self._body


def _settings_stub():
    return {
        "GEMINI_PROJECT_ID": "p",
        "GEMINI_LOCATION": "global",
        "GEMINI_MODEL": "gemini-2.5-pro",
        "GEMINI_MAX_OUTPUT_TOKENS": "32768",
        "GEMINI_SERVICE_ACCOUNT": "sa@example.iam.gserviceaccount.com",
    }


def _patch_token(monkeypatch):
    monkeypatch.setattr("app.integrations.gemini._access_token", lambda settings: "fake-token")


def test_max_tokens_is_a_failure_not_a_short_answer(monkeypatch):
    """A 2.5-series model spends output budget on thinking. An undersized cap
    returns an empty response with finishReason MAX_TOKENS, which must never be
    accepted as prose — truncated text in a customer-facing report is worse
    than no report."""
    _patch_token(monkeypatch)
    monkeypatch.setattr(
        "app.integrations.gemini.requests.post",
        lambda *a, **k: _FakeResponse(body={"candidates": [{"finishReason": "MAX_TOKENS"}]}),
    )
    with pytest.raises(GeminiError, match="maxOutputTokens"):
        _call_once(url="u", payload={}, settings=_settings_stub(), timeout=1)


def test_non_json_response_is_rejected(monkeypatch):
    _patch_token(monkeypatch)
    monkeypatch.setattr(
        "app.integrations.gemini.requests.post",
        lambda *a, **k: _FakeResponse(
            body={"candidates": [{"content": {"parts": [{"text": "not json"}]}}]}
        ),
    )
    with pytest.raises(GeminiError, match="not valid JSON"):
        _call_once(url="u", payload={}, settings=_settings_stub(), timeout=1)


def test_http_error_is_surfaced_with_its_status(monkeypatch):
    _patch_token(monkeypatch)
    monkeypatch.setattr(
        "app.integrations.gemini.requests.post",
        lambda *a, **k: _FakeResponse(status_code=403, text="permission denied"),
    )
    with pytest.raises(GeminiError, match="403"):
        _call_once(url="u", payload={}, settings=_settings_stub(), timeout=1)


def test_valid_response_is_parsed(monkeypatch):
    _patch_token(monkeypatch)
    monkeypatch.setattr(
        "app.integrations.gemini.requests.post",
        lambda *a, **k: _FakeResponse(
            body={"candidates": [{"content": {"parts": [{"text": '{"ok": true}'}]}}]}
        ),
    )
    parsed, usage = _call_once(url="u", payload={}, settings=_settings_stub(), timeout=1)
    assert parsed == {"ok": True}
    # No `usageMetadata` on this body, so the counts come back empty rather than
    # absent — `generate_json` records them on the generation span either way.
    assert usage == {}


def test_calls_are_never_made_as_a_person(monkeypatch):
    """The requirement behind the whole impersonation arrangement.

    A configured service account means `resolved_principal` must not fall back
    to Application Default Credentials. The test uses synthetic settings so it
    remains an offline unit test in CI.
    """
    monkeypatch.setattr(
        "app.integrations.gemini.google.auth.default",
        lambda **_: pytest.fail("service-account configuration must not read ADC"),
    )
    settings = _settings_stub()
    principal = resolved_principal(settings)
    assert principal.endswith(".iam.gserviceaccount.com"), (
        f"Vertex calls would be made as {principal!r}, not a service account. "
        "Set GEMINI_SERVICE_ACCOUNT before enabling Vertex requests."
    )
    assert "@example.test" not in principal


def test_a_transient_failure_is_retried_once(monkeypatch):
    """One retry, then the whole report fails. Enough to absorb a blip without
    turning a persistent outage into a slow one."""
    _patch_token(monkeypatch)
    monkeypatch.setattr("app.integrations.gemini.time.sleep", lambda s: None)
    calls = []

    def _flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return _FakeResponse(status_code=503, text="unavailable")
        return _FakeResponse(body={"candidates": [{"content": {"parts": [{"text": '{"ok":1}'}]}}]})

    monkeypatch.setattr("app.integrations.gemini.requests.post", _flaky)
    from app.integrations.gemini import generate_json

    result = generate_json(
        settings=_settings_stub(), system_instruction="s", user_content="u",
        response_schema={"type": "OBJECT"},
    )
    assert result == {"ok": 1}
    assert len(calls) == 2


def test_a_persistent_failure_is_not_retried_forever(monkeypatch):
    _patch_token(monkeypatch)
    monkeypatch.setattr("app.integrations.gemini.time.sleep", lambda s: None)
    calls = []
    monkeypatch.setattr(
        "app.integrations.gemini.requests.post",
        lambda *a, **k: (calls.append(1), _FakeResponse(status_code=500, text="boom"))[1],
    )
    from app.integrations.gemini import generate_json

    with pytest.raises(GeminiError):
        generate_json(
            settings=_settings_stub(), system_instruction="s", user_content="u",
            response_schema={"type": "OBJECT"},
        )
    assert len(calls) == 2


def test_rest_usage_is_relabelled_the_way_langfuse_aggregates():
    """The label set has to match `gemini_agent.usage_details_of` exactly, or a
    report's single-shot nodes and its tool-loop nodes land in different totals
    and the cache-hit rate stops meaning anything."""
    from app.integrations.gemini import usage_details_of_rest
    from app.integrations.gemini_agent import usage_details_of

    details = usage_details_of_rest(
        {
            "promptTokenCount": 1000,
            "candidatesTokenCount": 50,
            "totalTokenCount": 1100,
            "cachedContentTokenCount": 800,
            "thoughtsTokenCount": 50,
        }
    )
    assert details == {"input": 1000, "output": 50, "total": 1100, "cached": 800, "thoughts": 50}

    class _SdkUsage:
        prompt_token_count = 1000
        candidates_token_count = 50
        total_token_count = 1100
        cached_content_token_count = 800
        thoughts_token_count = 50

    assert set(details) == set(usage_details_of(_SdkUsage()))


def test_missing_usage_metadata_is_empty_not_an_error():
    from app.integrations.gemini import usage_details_of_rest

    assert usage_details_of_rest(None) == {}
    assert usage_details_of_rest({}) == {}
    assert usage_details_of_rest({"promptTokenCount": "lots"}) == {}
