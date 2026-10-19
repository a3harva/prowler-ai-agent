"""The only module that talks to Vertex AI.

Shaped like `integrations/prowler_runner.py`: the request builder is pure and
separate from the call, so the payload can be asserted in a test without a
network or a credential.

**Credentials.** Two modes, chosen by whether `GEMINI_SERVICE_ACCOUNT` is set:

- set — impersonate that service account, starting from whatever Application
  Default Credentials the process has. Locally that base credential is the
  developer's own `gcloud auth application-default login`, but every Vertex
  call is still made *as the service account*, and no key file exists anywhere
  on disk to leak or rotate. This is the local path.
- empty — use ADC directly. On a GCE host that is the attached service
  account via the metadata server, which is already the identity we want.

`resolved_principal()` exists so a test can assert which identity is actually
in play, rather than trusting that the impersonation was configured. The whole
point of this arrangement is "not a human's credentials", and that deserves an
assertion instead of an eyeball.
"""

from __future__ import annotations

import json
import time
from typing import Any

import google.auth
import requests
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request as AuthRequest

from app import observability
from app.services.errors import UnprocessableError

RETRY_BACKOFF_SECONDS = 5

# Vertex needs cloud-platform; nothing narrower covers generateContent.
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# The JSON the model must return for a pillar call. Declared to the API as a
# response schema rather than merely described in the prompt, so a malformed
# shape is the API's problem to reject rather than ours to parse around.
PILLAR_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "pillar_narrative": {"type": "STRING"},
        "findings": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "check_id": {"type": "STRING"},
                    "explanation": {"type": "STRING"},
                },
                "required": ["check_id", "explanation"],
            },
        },
    },
    "required": ["pillar_narrative", "findings"],
}

SUMMARY_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {"executive_summary": {"type": "STRING"}},
    "required": ["executive_summary"],
}


class GeminiError(UnprocessableError):
    """The model could not be reached, or did not return usable JSON.

    An `UnprocessableError` (422) rather than a 502: by the time this surfaces
    to a user it is attached to a failed report row, and the actionable reading
    is "this report could not be produced", not "a gateway is down".
    """


def build_endpoint(*, project_id: str, location: str, model: str) -> str:
    """`global` is not a regional prefix — it uses the bare host. Every other
    location prefixes it. Getting this wrong yields a 404 that reads like a
    missing model rather than a wrong URL."""
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    return (
        f"https://{host}/v1/projects/{project_id}/locations/{location}"
        f"/publishers/google/models/{model}:generateContent"
    )


def build_payload(
    *,
    system_instruction: str,
    user_content: str,
    response_schema: dict[str, Any],
    max_output_tokens: int,
) -> dict[str, Any]:
    """Pure. `maxOutputTokens` has to cover **thinking tokens as well as the
    answer** on 2.5-series models — a 20-token cap in testing spent 17 tokens
    thinking and returned an empty response with `finishReason: MAX_TOKENS`,
    which looks exactly like a model that refused rather than one that ran out
    of room."""
    return {
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        "generationConfig": {
            "maxOutputTokens": max_output_tokens,
            "temperature": 0.2,
            "responseMimeType": "application/json",
            "responseSchema": response_schema,
        },
    }


def _credentials(settings):
    source, _ = google.auth.default(scopes=_SCOPES)
    target = settings["GEMINI_SERVICE_ACCOUNT"].strip()
    if not target:
        return source
    return impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=target,
        target_scopes=_SCOPES,
        lifetime=3600,
    )


def resolved_principal(settings) -> str:
    """Whose identity a call would actually be made under. Used by the test
    that guards "this must never run as a person"."""
    target = settings["GEMINI_SERVICE_ACCOUNT"].strip()
    if target:
        return target
    creds = google.auth.default(scopes=_SCOPES)[0]
    creds.refresh(AuthRequest())
    return getattr(creds, "service_account_email", None) or "(application default credentials)"


def _access_token(settings) -> str:
    creds = _credentials(settings)
    creds.refresh(AuthRequest())
    return creds.token


def generate_json(
    *,
    settings,
    system_instruction: str,
    user_content: str,
    response_schema: dict[str, Any],
    timeout: float = 300.0,
) -> dict[str, Any]:
    """One structured call, with a single retry.

    The retry covers a transient malformed response or a rate limit; anything
    that survives it fails the whole report, per the all-or-nothing rule the
    import pipeline already follows. A half-written customer-facing document is
    worse than a clear failure to retry.
    """
    url = build_endpoint(
        project_id=settings["GEMINI_PROJECT_ID"],
        location=settings["GEMINI_LOCATION"],
        model=settings["GEMINI_MODEL"],
    )
    payload = build_payload(
        system_instruction=system_instruction,
        user_content=user_content,
        response_schema=response_schema,
        max_output_tokens=int(settings["GEMINI_MAX_OUTPUT_TOKENS"]),
    )

    model = settings["GEMINI_MODEL"]
    # Traced here rather than in `_call_once`, so a retried call is one
    # generation with `attempts=2` rather than two generations — the same shape
    # `gemini_agent.generate` produces, and the reason the two are comparable in
    # the UI at all. Without this the six single-shot nodes (survey, correlate,
    # plan_remediation, compose, summarize, critique) had node spans with no
    # model call inside them: their tokens, latency and cost were invisible,
    # which is most of a deep report's spend.
    with observability.observation(
        f"gemini · {model}",
        as_type="generation",
        model=model,
        input={"system_instruction": system_instruction, "user_content": user_content},
        model_parameters={
            "max_output_tokens": int(settings["GEMINI_MAX_OUTPUT_TOKENS"]),
            "response_mime_type": "application/json",
        },
    ) as span:
        for attempt in (1, 2):
            started = time.monotonic()
            try:
                parsed, usage = _call_once(
                    url=url, payload=payload, settings=settings, timeout=timeout
                )
            except GeminiError as exc:
                if attempt == 2:
                    span.update(level="ERROR", status_message=str(exc)[:300])
                    raise
                # A brief pause before the retry. The failure this is most likely
                # to absorb is a 429, and retrying a rate limit with no delay at
                # all mostly just spends the second attempt earning the same
                # answer.
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
            span.update(
                output=parsed,
                usage_details=usage_details_of_rest(usage),
                metadata={
                    "attempts": attempt,
                    "latency_ms": int((time.monotonic() - started) * 1000),
                },
            )
            return parsed
    raise AssertionError("unreachable")


def usage_details_of_rest(usage: dict[str, Any] | None) -> dict[str, int]:
    """`usageMetadata` off the REST response, named the way Langfuse aggregates.

    A separate function from `gemini_agent.usage_details_of` because the wire
    shapes genuinely differ — the SDK hands back an object with snake_case
    attributes, the REST API a dict with camelCase keys — and collapsing them
    into one would mean a getattr-or-getitem branch on every field. The **label
    set is identical**, which is what actually has to match: it is the key
    Langfuse aggregates cost and cache-hit rate on, so a report's single-shot
    nodes and its tool-loop nodes land in the same totals.
    """
    if not usage:
        return {}
    fields = {
        "input": "promptTokenCount",
        "output": "candidatesTokenCount",
        "total": "totalTokenCount",
        "cached": "cachedContentTokenCount",
        "thoughts": "thoughtsTokenCount",
    }
    return {
        label: usage[key]
        for label, key in fields.items()
        if isinstance(usage.get(key), int)
    }


def _call_once(
    *, url: str, payload: dict[str, Any], settings, timeout: float
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns the parsed JSON **and** the response's `usageMetadata`.

    The usage rides back with the answer rather than being read by the caller
    off a second call, because there is no second call to read it from — the
    counts exist only on the response body this function already parsed."""
    try:
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {_access_token(settings)}"},
            json=payload,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise GeminiError(f"could not reach Vertex AI: {exc}") from exc

    if response.status_code != 200:
        raise GeminiError(f"Vertex AI returned {response.status_code}: {response.text[:300]}")

    body = response.json()
    candidates = body.get("candidates") or []
    if not candidates:
        # A safety block arrives this way — no candidate at all, with the
        # reason on the prompt feedback rather than on a candidate.
        raise GeminiError(f"no candidate returned: {json.dumps(body.get('promptFeedback', {}))[:300]}")

    candidate = candidates[0]
    if candidate.get("finishReason") == "MAX_TOKENS":
        raise GeminiError(
            "response hit maxOutputTokens — truncated prose must not reach a customer-facing report"
        )

    parts = candidate.get("content", {}).get("parts") or []
    text = "".join(part.get("text", "") for part in parts).strip()
    if not text:
        raise GeminiError(f"empty response (finishReason={candidate.get('finishReason')})")

    try:
        return json.loads(text), body.get("usageMetadata") or {}
    except json.JSONDecodeError as exc:
        raise GeminiError(f"response was not valid JSON: {exc}") from exc
