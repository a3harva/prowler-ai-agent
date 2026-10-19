"""The tool-calling client, built on the `google-genai` SDK.

Separate from `integrations/gemini.py` rather than replacing it. That module
hand-builds a Vertex REST call for the report path's single-shot structured
JSON, and it is correct for that; `tests/test_gemini.py` asserts its payload
shape directly. Migrating it is a worthwhile follow-up but it is regression
surface on a customer-facing document for no functional gain today, so the two
coexist for now and share nothing but the credentials helper.

**Why the SDK here and not more hand-rolled REST.** Gemini 3 models return an
encrypted `thought_signature` on function calls and *enforce that it is passed
back* on the next request — omit it and you get a hard 400 reading "Function
call ... is missing a thought_signature". It was optional on 2.5 and is
mandatory on 3. Google's own documentation is explicit that the SDKs handle
this automatically provided you append the full response object to history,
and that you only deal with signatures by hand when using the REST API. An
agent loop on raw REST therefore means hand-rolling round-trip handling of an
opaque encrypted state token, where a subtle mistake surfaces as a 400 that
reads like a malformed request. That is not a thing worth owning.

**Automatic Function Calling is deliberately never used.** The SDK executes
Python callables on the model's behalf if you hand it any. We hand it schemas
only. AFC would bypass `services/agent_tools.py::dispatch` — the single layer
where the session's project binding is injected — and would execute writes
without the confirmation gate. Declaring schemas rather than callables is what
makes that structurally impossible rather than merely intended.

Credentials are unchanged from `integrations/gemini.py`: the same impersonated
credentials object is passed straight to the client, so `resolved_principal()`
and the "never runs as a person" guard keep their meaning.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any

from google import genai
from google.genai import types

from app import observability
from app.integrations.gemini import _credentials  # same impersonation, one definition
from app.services.errors import UnprocessableError

logger = logging.getLogger(__name__)

# A chat turn, not a report. `integrations/gemini.py` waits 300s because a
# report is generated once and a person is not watching; here one is.
#
# Sized to allow a response and its tool calls to complete without turning a
# slow answer into a request failure. THINKING_LEVEL below controls the
# latency/quality trade-off; this is the associated headroom.
REQUEST_TIMEOUT_SECONDS = 120

# The report investigator's own ceiling. It thinks harder (see
# REPORT_THINKING_LEVEL) and nobody is waiting on it, so the chat turn's budget
# is the wrong one — and a 504 here costs a whole pillar's investigation rather
# than one chat reply. Matches what `integrations/gemini.py` already waits for
# the report path's single-shot calls.
REPORT_REQUEST_TIMEOUT_SECONDS = 300

# 3.x models think by default at a level suited to hard single-shot reasoning,
# which is the wrong trade for a conversational turn: the per-turn reasoning
# load is modest and latency matters to the person waiting for a response.
#
# **This used to be one constant applied to both callers of `build_config`, and
# the comment claimed it was chat-only.** It was not. `build_config` is called
# by `services/agent.py` (chat) *and* by `agents/report_nodes.py`'s
# `investigate_pillar`, so the report's one tool-calling node silently inherited
# a level tuned for a latency-sensitive chat turn. The claim was true only of
# `gemini.py::generate_json`, which is the six single-shot report nodes.
#
# That was harmless while the investigator only queried the database. It stops
# being harmless once it reconciles scanned state against live cloud state —
# "this ACL is on an instance that is stopped, so check ipv4Enabled" is exactly
# the reasoning `low` trades away — and the latency argument does not apply to
# a report nobody is watching. Hence two constants, differing deliberately.
CHAT_THINKING_LEVEL = "low"
REPORT_THINKING_LEVEL = "medium"

# Thought summaries, for the trace. Separate from the level above: the SDK
# exposes `include_thoughts` and `thinking_level` as independent fields, so
# asking to *see* the reasoning does not change how much of it happens. Costs a
# small number of output tokens; worth it, because "what was the agent
# thinking" is the question a trace is opened to answer.
INCLUDE_THOUGHTS = True

# Backwards-compatible alias. Kept because removing a module constant that
# other code may import is a separate change from fixing which paths use it.
THINKING_LEVEL = CHAT_THINKING_LEVEL

# Bounded so a loop terminates. Reached only by a model that keeps calling
# tools without ever answering, which is a failure worth surfacing rather than
# absorbing.
MAX_TOOL_ROUNDS = 12

_RETRYABLE_MARKERS = ("429", "500", "502", "503", "504", "RESOURCE_EXHAUSTED", "UNAVAILABLE")


class AgentModelError(UnprocessableError):
    """The model could not be reached, or refused. A 422 rather than a 502 for
    the same reason `GeminiError` is: by the time a user sees it, the
    actionable reading is "this message could not be answered"."""


def build_client(settings, *, timeout_seconds: int = REQUEST_TIMEOUT_SECONDS) -> genai.Client:
    """`timeout_seconds` is a parameter for the same reason the thinking level
    is two constants: a chat turn and a report investigation want different
    patience. 120s is headroom for a person waiting; the report path passes
    `REPORT_REQUEST_TIMEOUT_SECONDS`, matching what `gemini.py` already waits
    for its own single-shot calls."""
    return genai.Client(
        vertexai=True,
        project=settings["GEMINI_PROJECT_ID"],
        location=settings["GEMINI_LOCATION"],
        credentials=_credentials(settings),
        http_options=types.HttpOptions(timeout=timeout_seconds * 1000),
    )


def build_config(
    *,
    settings,
    function_declarations: list[dict],
    system_instruction: str,
    thinking_level: str = CHAT_THINKING_LEVEL,
):
    """Tools as schemas only — see the module docstring on why never callables.

    `mode=AUTO` rather than ANY: the model must be free to answer without
    calling anything, since plenty of turns are follow-up questions about what
    it already fetched. Tool-selection quality is known to degrade past roughly
    fifty declarations; at fifteen there is no need to narrow the set per turn.

    `thinking_level` defaults to the chat value rather than being required, so
    the chat path reads unchanged — but the report path now passes its own
    explicitly instead of inheriting one by accident.
    """
    return types.GenerateContentConfig(
        system_instruction=system_instruction,
        temperature=0.2,
        max_output_tokens=int(settings["GEMINI_AGENT_MAX_OUTPUT_TOKENS"]),
        thinking_config=types.ThinkingConfig(
            thinking_level=thinking_level, include_thoughts=INCLUDE_THOUGHTS
        ),
        tools=[
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(**decl) for decl in function_declarations
                ]
            )
        ],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode=types.FunctionCallingConfigMode.AUTO
            )
        ),
    )


def generate(*, client: genai.Client, settings, contents: list, config) -> Any:
    """One request, with backoff on the failures that are worth retrying.

    Replaces the report path's flat `sleep(5)` + single retry. A 429 retried
    immediately mostly spends the second attempt earning the same answer; a
    400 retried at all is us re-sending our own bug. Jitter matters because
    several users hitting the same quota ceiling will otherwise retry in
    lockstep.
    """
    model = settings["GEMINI_AGENT_MODEL"]
    # One observation for the whole call including its retries, rather than one
    # per attempt. A retried 429 is one logical model call that took longer, and
    # splitting it into three would make the trace's latency and cost read as
    # three calls that never happened.
    with observability.observation(
        f"gemini · {model}",
        as_type="generation",
        model=model,
        input=_traceable_contents(contents),
        model_parameters=_traceable_config(config),
    ) as span:
        last: Exception | None = None
        for attempt in range(3):
            try:
                started = time.monotonic()
                response = client.models.generate_content(
                    model=model, contents=contents, config=config
                )
                usage = getattr(response, "usage_metadata", None)
                latency_ms = int((time.monotonic() - started) * 1000)
                logger.info(
                    "gemini_agent call model=%s attempt=%d latency_ms=%d "
                    "prompt_tokens=%s candidate_tokens=%s total_tokens=%s cached=%s thoughts=%s",
                    model,
                    attempt + 1,
                    latency_ms,
                    getattr(usage, "prompt_token_count", None),
                    getattr(usage, "candidates_token_count", None),
                    getattr(usage, "total_token_count", None),
                    getattr(usage, "cached_content_token_count", None),
                    getattr(usage, "thoughts_token_count", None),
                )
                span.update(
                    output=_traceable_response(response),
                    usage_details=usage_details_of(usage),
                    metadata={
                        "attempts": attempt + 1,
                        "latency_ms": latency_ms,
                        # The reason a trace is opened. Summaries only — the raw
                        # reasoning is not returned by the API, and the encrypted
                        # thought_signature is deliberately not traced: it is
                        # opaque, large, and belongs only in the request history.
                        "thinking": thoughts_of(response),
                    },
                )
                return response
            except Exception as exc:  # noqa: BLE001 — the SDK raises several types
                last = exc
                text = str(exc)
                if not any(marker in text for marker in _RETRYABLE_MARKERS) or attempt == 2:
                    span.update(level="ERROR", status_message=text[:300])
                    raise AgentModelError(f"the model could not answer: {text[:300]}") from exc
                backoff = (2**attempt) + random.uniform(0, 0.5)
                logger.warning("gemini_agent retrying in %.1fs after: %s", backoff, text[:200])
                time.sleep(backoff)
        span.update(level="ERROR", status_message=str(last)[:300])
        raise AgentModelError(f"the model could not answer: {last}")


# ── what the trace gets ──────────────────────────────────────────────────────
# All three are best-effort by construction. A `types.Content` holds bytes
# (inline data, thought signatures) that do not serialise cleanly, and a
# tracing helper that raises would fail the report it is describing — which is
# the one thing observability must never do.


def usage_details_of(usage) -> dict[str, int]:
    """Token counts, named the way Langfuse aggregates them.

    `cached` is the number this whole prefix-stability effort is judged on:
    it is the only evidence that a stable system instruction is actually being
    reused rather than merely looking stable in the source.
    """
    if usage is None:
        return {}
    fields = {
        "input": "prompt_token_count",
        "output": "candidates_token_count",
        "total": "total_token_count",
        "cached": "cached_content_token_count",
        "thoughts": "thoughts_token_count",
    }
    details: dict[str, int] = {}
    for label, attr in fields.items():
        value = getattr(usage, attr, None)
        if isinstance(value, int):
            details[label] = value
    return details


def thoughts_of(response) -> list[str]:
    """The model's thought summaries, if it returned any.

    Marked by `part.thought`, which sits beside `part.thought_signature` — the
    former is readable text, the latter is the encrypted token that must be
    echoed back and must never be treated as content.
    """
    try:
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            return []
        parts = getattr(candidates[0].content, "parts", None) or []
        return [p.text for p in parts if getattr(p, "thought", False) and getattr(p, "text", None)]
    except Exception:  # noqa: BLE001
        return []


def _traceable_contents(contents: list) -> Any:
    """The conversation as sent, flattened enough to read in a trace UI.

    Function calls and their results are the interesting part of an agent turn,
    so they are named rather than rendered as `<Part>` repr noise.
    """
    try:
        out = []
        for content in contents:
            role = getattr(content, "role", "?")
            rendered: list[Any] = []
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "function_call", None) is not None:
                    call = part.function_call
                    rendered.append({"function_call": call.name, "args": dict(call.args or {})})
                elif getattr(part, "function_response", None) is not None:
                    rendered.append({"function_response": part.function_response.name})
                elif getattr(part, "thought", False):
                    rendered.append({"thought": getattr(part, "text", "")})
                elif getattr(part, "text", None):
                    rendered.append(part.text)
            out.append({"role": role, "parts": rendered})
        return out
    except Exception:  # noqa: BLE001
        return "«contents could not be rendered for tracing»"


def _traceable_response(response) -> Any:
    try:
        calls = [
            {"name": c.name, "args": dict(c.args or {})} for c in (function_calls_of(response) or [])
        ]
        return {"text": text_of(response), "function_calls": calls}
    except Exception:  # noqa: BLE001
        return "«response could not be rendered for tracing»"


def _traceable_config(config) -> dict[str, Any]:
    try:
        thinking = getattr(config, "thinking_config", None)
        return {
            "temperature": getattr(config, "temperature", None),
            "max_output_tokens": getattr(config, "max_output_tokens", None),
            "thinking_level": getattr(thinking, "thinking_level", None),
            "tool_count": len(getattr(config.tools[0], "function_declarations", []) or [])
            if getattr(config, "tools", None)
            else 0,
        }
    except Exception:  # noqa: BLE001
        return {}


def function_calls_of(response) -> list:
    """Every `functionCall` part of a response, or an empty list.

    Read off the response object rather than reconstructed, because the object
    is also what gets appended to history — that is precisely what carries the
    thought signatures the next request must echo back.
    """
    calls = getattr(response, "function_calls", None)
    return list(calls) if calls else []


def text_of(response) -> str:
    try:
        return (response.text or "").strip()
    except (AttributeError, ValueError):
        # `.text` raises rather than returning None when the candidate holds
        # only function calls — a normal state mid-loop, not an error.
        return ""


def model_content_of(response):
    """The model's own turn, to be appended to history verbatim.

    Returning `candidate.content` rather than rebuilding a `Content` from the
    text is the whole thought-signature contract: the signature rides on the
    part objects, and a prettified reconstruction drops it and earns a 400 on
    the next call.
    """
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        raise AgentModelError("the model returned no candidate")
    return candidates[0].content


def tool_response_content(results: list[tuple[str, str | None, dict]]):
    """**One** content carrying **every** tool result of a round.

    This takes a list rather than a single result because the API counts:

        "Please ensure that the number of function response parts is equal to
        the number of function call parts of the function call turn."

    A model may emit several `functionCall` parts in one turn — asking for a
    summary and the service breakdown together, say. All of their responses
    must come back as parts of a single following content. Appending one
    content per result instead produces N separate turns against one call
    turn, and the request is rejected with a 400 that names the part count
    rather than the shape, which is easy to misread as a malformed part.

    `id` is echoed back when the model supplied one — Gemini 3 returns a
    unique id per function call and uses it to map results onto requests,
    which is what keeps parallel results from being matched up wrongly once
    they share a content.
    """
    parts = []
    for name, call_id, result in results:
        part = types.Part.from_function_response(name=name, response=result)
        if call_id and getattr(part, "function_response", None) is not None:
            try:
                part.function_response.id = call_id
            except (AttributeError, ValueError):
                pass
        parts.append(part)
    return types.Content(role="user", parts=parts)


def user_content(text: str):
    return types.Content(role="user", parts=[types.Part.from_text(text=text)])


def content_from_stored(role: str, parts: list[dict]):
    """Rebuild a stored turn for replay.

    `parts` is the raw part list as it arrived, persisted on `agent_messages`
    — including `thought_signature`. `Content.model_validate` reconstitutes it
    with the signature intact, which is what makes a conversation resumable
    across requests at all.
    """
    return types.Content.model_validate({"role": role, "parts": parts})


def parts_to_stored(content) -> list[dict]:
    """Serialise a turn for persistence, signatures and all."""
    try:
        dumped = content.model_dump(mode="json", exclude_none=True)
    except AttributeError:
        return []
    return dumped.get("parts") or []
