"""Tracing for the agent, and the guarantee that it can never break one.

Report generation is unattended and customer-facing. A telemetry library that
can fail a report is worse than no telemetry at all, so **every function in this
module is safe to call unconditionally**, whether or not Langfuse is
configured, reachable, or working. There is no `if tracing_enabled:` at any call
site — that condition lives here, once.

Three properties hold that up:

1.  **Absent configuration is a supported state, not a broken one.** Empty
    `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` resolve to a null client and
    everything below becomes a no-op. This is the same "empty means something"
    convention `GEMINI_SERVICE_ACCOUNT` uses, and it is why the keys are
    required to be *present* in `CONFIG_KEYS` but allowed to be blank.

2.  **Every SDK call is wrapped.** The library is fire-and-forget by design and
    buffers off-thread, but construction can raise on malformed config and
    `flush()` can block on a dead collector. A raise from any of it must not
    reach the graph.

3.  **The null objects have the same shape as the real ones.** A context manager
    that yields a no-op span rather than `None` means a caller cannot write
    `span.update(...)` and have it explode when tracing is off — the failure
    mode that makes optional instrumentation rot.

**Redaction happens inside the SDK, not around it.** `mask=` is Langfuse's own
hook and runs over every input, output and metadata value the client is about
to send, including ones a future call site forgets to sanitise. Sanitising at
call sites instead would be one `logger.info`-shaped mistake away from shipping
a credential.

What is deliberately *not* redacted: GCP project ids, resource names, service
account emails, bucket names, IP addresses. Those are the substance of a trace —
a run you cannot read is not observability. Keeping them safe is what
self-hosting is for; see `docker-compose.langfuse.yml`.
"""

from __future__ import annotations

import contextlib
import logging
import re
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Set once, on first use, and never re-resolved. Three states, and `False` is
# meaningfully different from `None`: `None` means "not yet resolved", `False`
# means "resolved, and tracing is off" — so a failed construction is not retried
# on every span for the life of the process.
_client: Any = None
_resolved = False

# ── redaction ────────────────────────────────────────────────────────────────
# Shapes, not names. A denylist of key names ("password", "token") misses
# `authorization_header` and `x_api_key_2`, while these match the thing itself
# wherever it appears — including inside a stack trace or a shell error string,
# which is exactly where a credential leaks from in practice.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Google OAuth access tokens. The dominant real risk here: gcloud prints
    # them in error output, and that output is fed straight to the model.
    (re.compile(r"\bya29\.[A-Za-z0-9._\-]{20,}"), "«redacted:google-oauth-token»"),
    # Service account private keys, should one ever reach a log line.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "«redacted:private-key»"),
    # JWTs — our own access/refresh tokens, and Google id tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "«redacted:jwt»"),
    # Langfuse's own keys, so a misconfiguration cannot echo them into a trace.
    (re.compile(r"\b[ps]k-lf-[A-Za-z0-9\-]{8,}"), "«redacted:langfuse-key»"),
    # Generic bearer headers.
    (re.compile(r"(?i)\b(authorization|bearer)\s*[:=]\s*\S+"), r"\1 «redacted»"),
    # Anything that names itself a secret and then gives one.
    (re.compile(r"(?i)\b([a-z0-9_\-]*(?:secret|password|api[_\-]?key|private[_\-]?key)"
                r"[a-z0-9_\-]*)\s*[:=]\s*[\"']?([^\s\"',}]{4,})"),
     r"\1=«redacted»"),
)

# A trace value is not a place to put a megabyte. Long values are truncated
# with a marker rather than dropped, so a reader can tell the difference between
# "there was nothing here" and "there was too much".
_MAX_STRING = 60_000
_MAX_DEPTH = 12


def _redact_text(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > _MAX_STRING:
        return text[:_MAX_STRING] + f"\n«truncated: {len(text) - _MAX_STRING} more characters»"
    return text


def mask(*, data: Any) -> Any:
    """Langfuse's `mask=` hook: runs over everything the client sends.

    Recurses rather than stringifying, so a secret nested three dicts deep in a
    tool result is still caught — and so structured data stays structured in the
    UI, which is most of why the trace is worth reading.

    Never raises. A redaction function that throws would take down the very
    thing it is protecting, so a failure here degrades to a marker.
    """
    try:
        return _mask_value(data, depth=0)
    except Exception:  # noqa: BLE001 — see the docstring
        return "«redaction failed; value withheld»"


def _mask_value(value: Any, *, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        return "«max depth»"
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: _mask_value(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_value(v, depth=depth + 1) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _redact_text(str(value))


# ── the client ───────────────────────────────────────────────────────────────


def client() -> Any:
    """The process-wide client, or `None` when tracing is off.

    Resolved once. Call sites should not use this directly — the context
    managers below exist so that no call site has to know tracing can be off.
    """
    global _client, _resolved
    if _resolved:
        return _client

    _resolved = True
    try:
        from app.config import get_settings

        settings = get_settings()
        public_key = settings["LANGFUSE_PUBLIC_KEY"].strip()
        secret_key = settings["LANGFUSE_SECRET_KEY"].strip()
        host = settings["LANGFUSE_HOST"].strip()

        if not public_key or not secret_key:
            logger.info("langfuse disabled: no credentials configured")
            _client = None
            return None

        from langfuse import Langfuse

        _client = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
            mask=mask,
            environment=settings.app_env,
            # Never block the graph waiting on the collector. The default is
            # more patient than a report generator should be.
            timeout=10,
        )
        logger.info("langfuse enabled host=%s environment=%s", host, settings.app_env)
    except Exception as exc:  # noqa: BLE001
        # Deliberately swallowed. A misconfigured collector must not stop a
        # report from being generated, and this is the one place that decision
        # is made.
        logger.warning("langfuse disabled: client construction failed: %s", exc)
        _client = None
    return _client


def enabled() -> bool:
    return client() is not None


def flush() -> None:
    """Push buffered spans. Call in a Celery task's `finally`.

    The SDK batches off-thread, and a prefork child that exits — or is recycled
    after `max_tasks_per_child` — takes its unflushed buffer with it. Without
    this, the traces most worth having (the long, expensive, late ones) are
    exactly the ones lost.
    """
    c = client()
    if c is None:
        return
    try:
        c.flush()
    except Exception as exc:  # noqa: BLE001
        logger.warning("langfuse flush failed: %s", exc)


def reset_for_tests() -> None:
    """Drop the cached client so a test can change configuration.

    Only for tests. Production resolves once by design.
    """
    global _client, _resolved
    _client = None
    _resolved = False


# ── null objects ─────────────────────────────────────────────────────────────


class _NullSpan:
    """Same surface as a Langfuse span, minus the behaviour.

    Yielded whenever tracing is off, so instrumentation at a call site is
    written once, unconditionally, and does not need a `None` check that
    someone will eventually forget.
    """

    def update(self, **kwargs: Any) -> "_NullSpan":
        return self

    def score(self, **kwargs: Any) -> "_NullSpan":
        return self

    def score_trace(self, **kwargs: Any) -> "_NullSpan":
        return self

    def create_event(self, **kwargs: Any) -> "_NullSpan":
        return self

    def end(self, **kwargs: Any) -> "_NullSpan":
        return self


NULL_SPAN = _NullSpan()


class _SafeSpan:
    """A real span with every method wrapped.

    The SDK does not generally raise from these, but "generally" is not a
    property a customer-facing document should depend on, and the wrapping costs
    nothing measurable against a model call.
    """

    __slots__ = ("_span",)

    def __init__(self, span: Any) -> None:
        self._span = span

    def _call(self, method: str, **kwargs: Any) -> "_SafeSpan":
        try:
            getattr(self._span, method)(**kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("langfuse %s failed: %s", method, exc)
        return self

    def update(self, **kwargs: Any) -> "_SafeSpan":
        return self._call("update", **kwargs)

    def score(self, **kwargs: Any) -> "_SafeSpan":
        return self._call("score", **kwargs)

    def score_trace(self, **kwargs: Any) -> "_SafeSpan":
        return self._call("score_trace", **kwargs)

    def create_event(self, **kwargs: Any) -> "_SafeSpan":
        return self._call("create_event", **kwargs)

    def end(self, **kwargs: Any) -> "_SafeSpan":
        return self._call("end", **kwargs)


# ── the call-site surface ────────────────────────────────────────────────────


@contextlib.contextmanager
def observation(
    name: str,
    *,
    as_type: str = "span",
    input: Any = None,
    metadata: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Iterator[Any]:
    """One nested observation. Always yields something with a span's methods.

    `as_type` follows Langfuse's own vocabulary — `span` for a step,
    `generation` for a model call, `tool` for a tool or command invocation,
    `agent` for a reasoning loop. Using the right one is not cosmetic: the UI
    aggregates cost and latency by type, so a model call recorded as a plain
    span is invisible in exactly the view you opened the trace to look at.
    """
    c = client()
    if c is None:
        yield NULL_SPAN
        return

    try:
        cm = c.start_as_current_observation(
            name=name, as_type=as_type, input=input, metadata=metadata, **kwargs
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("langfuse observation %r failed to start: %s", name, exc)
        yield NULL_SPAN
        return

    try:
        with cm as span:
            yield _SafeSpan(span)
    except Exception:
        # The body raised. Let it through untouched — a failing node must fail
        # the graph exactly as it would without tracing. The span is closed by
        # the SDK's own context manager and carries the exception.
        raise


@contextlib.contextmanager
def trace_run(
    name: str,
    *,
    trace_name: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    input: Any = None,
) -> Iterator[Any]:
    """The root observation of a run, with trace-level attributes attached.

    `propagate_attributes` has to wrap the root span rather than be called
    inside it: attributes reach the active span and every span created after,
    and nothing retroactively. Entered here, in the one place a run begins, so
    no node has to remember it.
    """
    c = client()
    if c is None:
        yield NULL_SPAN
        return

    try:
        from langfuse import propagate_attributes
    except Exception:  # noqa: BLE001
        propagate_attributes = None  # type: ignore[assignment]

    with observation(name, input=input, metadata=metadata) as span:
        # An ExitStack rather than a `with` wrapped in try/except, and the
        # difference is a real bug rather than a style preference.
        #
        # `try: with propagate_attributes(...): yield span / except: yield span`
        # looks like it guards the entry. It does not: an exception raised by
        # the *caller's body* is thrown back in at the `yield`, unwinds through
        # `__exit__`, and lands in that same `except` — which then yields a
        # second time. A @contextmanager generator that yields twice raises
        # `RuntimeError: generator didn't stop after throw()`, so a failing
        # report would surface as a confusing tracing error instead of its own
        # exception. Guarding only the entry keeps the body's exception intact,
        # which is the transparency promise this module makes.
        stack = contextlib.ExitStack()
        if propagate_attributes is not None:
            try:
                stack.enter_context(
                    propagate_attributes(
                        trace_name=trace_name or name,
                        user_id=user_id,
                        session_id=session_id,
                        tags=tags,
                        metadata=metadata,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("langfuse propagate_attributes failed: %s", exc)
        try:
            yield span
        finally:
            try:
                stack.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("langfuse attribute context close failed: %s", exc)


def capture_context() -> Any:
    """The current OpenTelemetry context, to be re-attached on another thread.

    **Why this is needed at all.** Langfuse's spans nest through an OTel
    context stored in a `contextvar`, and `contextvars` are per-thread.
    LangGraph runs its nodes through a `ThreadPoolExecutor`, which does not
    copy the submitting thread's context — so a node body starts with an empty
    context, `start_as_current_observation` finds no parent, and **every node
    becomes the root of its own trace**. One report then renders as a hundred
    unrelated traces, each holding a fragment of the run.

    The failure is quiet and easy to misread: spans and their own children nest
    perfectly *within* a node, so the instrumentation looks correct everywhere
    you check, and only the top-level grouping is wrong.

    Worth knowing before reproducing it: a trivial graph compiled with **no
    checkpointer** runs its node inline on the calling thread and nests fine.
    The executor only appears with a real checkpointer, so a minimal repro
    disproves the bug rather than confirming it.
    """
    try:
        from opentelemetry import context as otel_context

        return otel_context.get_current()
    except Exception:  # noqa: BLE001
        return None


@contextlib.contextmanager
def use_context(ctx: Any) -> Iterator[None]:
    """Re-attach a context captured by `capture_context` on this thread.

    A no-op for `None`, so a caller does not have to know whether tracing is on
    or whether the capture succeeded.
    """
    if ctx is None:
        yield
        return
    try:
        from opentelemetry import context as otel_context

        token = otel_context.attach(ctx)
    except Exception as exc:  # noqa: BLE001
        logger.debug("langfuse context attach failed: %s", exc)
        yield
        return
    try:
        yield
    finally:
        try:
            otel_context.detach(token)
        except Exception as exc:  # noqa: BLE001
            logger.debug("langfuse context detach failed: %s", exc)


def score(span: Any, name: str, value: float | str, *, comment: str | None = None) -> None:
    """A run-level score, recorded against the run's own span.

    Deliberately takes the span rather than reaching for "the current trace":
    the client-level `create_score` needs a `trace_id` to be unambiguous, and a
    score silently attached to the wrong run is worse than no score, because it
    is a number someone will later compare against.

    Scores are what make a run comparable to the one before it — gate pass
    rates and revision counts are what say whether a prompt change helped, and
    reading that off individual traces by eye does not scale.
    """
    try:
        span.score_trace(
            name=name,
            value=value,
            data_type="CATEGORICAL" if isinstance(value, str) else "NUMERIC",
            comment=comment,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("langfuse score %r failed: %s", name, exc)


__all__ = [
    "NULL_SPAN",
    "capture_context",
    "client",
    "enabled",
    "flush",
    "mask",
    "observation",
    "reset_for_tests",
    "score",
    "trace_run",
    "use_context",
]
