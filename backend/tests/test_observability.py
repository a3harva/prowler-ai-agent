"""The guarantee this module exists to make is that it cannot break a report.

These tests are about that guarantee, not about whether spans reach Langfuse.
Asserting that a trace arrived would need a collector and would test the SDK;
asserting that a *broken* collector changes nothing is what actually protects
the customer-facing document, and it needs no network at all.
"""

from __future__ import annotations

import pytest

from app import observability as obs


@pytest.fixture(autouse=True)
def _clean_client():
    """Each test resolves the client itself. Production resolves once by design,
    which would otherwise leak one test's configuration into the next."""
    obs.reset_for_tests()
    yield
    obs.reset_for_tests()


# ── redaction ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "secret",
    [
        "ya29.a0AfH6SMBx" + "x" * 40,
        ".".join(
            (
                "eyJhbGciOiJIUzI1NiJ9",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            )
        ),
        "sk-lf-11111111-2222-3333-4444-555555555555",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
    ],
)
def test_a_credential_never_survives_masking(secret):
    """Each value has a shape that can appear in cloud command output sent to
    a model and therefore into a trace."""
    assert secret not in str(obs.mask(data=secret))


def test_a_credential_nested_in_a_tool_result_is_still_caught():
    """Recursion, not stringification. A tool result is a dict of dicts, and a
    top-level-only mask would ship this."""
    payload = {
        "rows": [{"env": {"GOOGLE_TOKEN": "ya29." + "z" * 40}}],
        "count": 1,
    }
    assert "ya29." not in str(obs.mask(data=payload))


def test_masking_keeps_the_data_worth_reading():
    """A trace nobody can read is not observability. Project ids, resource
    names, service accounts and IPs are the substance and must survive —
    keeping them safe is what self-hosting is for."""
    payload = {
        "project_id": "synthetic-project-id",
        "service_account": "scanner@synthetic-project.invalid",
        "external_ip": "198.51.100.17",
        "bucket": "gs://demo-security-ops-website-bucket",
    }
    out = obs.mask(data=payload)
    assert out == payload


def test_masking_preserves_structure():
    """Structured data must stay structured, or the UI shows one long string."""
    out = obs.mask(data={"a": [1, 2, {"b": "plain"}], "c": None, "d": True})
    assert out == {"a": [1, 2, {"b": "plain"}], "c": None, "d": True}


def test_an_oversized_value_is_truncated_and_says_so():
    """Truncated, not dropped — a reader must be able to tell "nothing here"
    from "too much here"."""
    out = obs.mask(data="x" * 200_000)
    assert len(out) < 200_000
    assert "truncated" in out


def test_masking_never_raises():
    """A redaction function that throws takes down the thing it protects."""

    class Hostile:
        def __str__(self):
            raise RuntimeError("nope")

    assert isinstance(obs.mask(data=Hostile()), str)


# ── disabled is a supported state ────────────────────────────────────────────


def test_no_credentials_means_disabled_not_broken(monkeypatch):
    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", None, raising=False)
    assert obs.enabled() is False


def test_every_call_site_works_with_tracing_off(monkeypatch):
    """The property that lets instrumentation be written unconditionally: with
    tracing off, a call site must still be able to use the span it was given."""
    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", None, raising=False)

    with obs.trace_run("report", trace_name="r", user_id="u", tags=["deep"]) as root:
        root.update(output="done")
        obs.score(root, "gate_pass", 1.0)
        with obs.observation("node", as_type="span", input={"x": 1}) as span:
            span.update(output={"y": 2})
            span.create_event(name="gate", metadata={"gate": "C1"})
    obs.flush()


def test_the_null_span_and_the_real_wrapper_have_the_same_shape():
    """A method on one and not the other is how optional instrumentation rots:
    it works until tracing is switched on, or off, and then it does not."""
    null_methods = {m for m in dir(obs.NULL_SPAN) if not m.startswith("_")}
    safe_methods = {m for m in dir(obs._SafeSpan) if not m.startswith("_")}
    assert null_methods == safe_methods


# ── a broken collector must not break a run ──────────────────────────────────


def test_a_client_that_fails_to_construct_disables_tracing(monkeypatch):
    """Rather than raising into whatever was being generated at the time."""
    import app.config

    monkeypatch.setattr(
        app.config, "get_settings", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert obs.client() is None
    assert obs.enabled() is False


def test_a_span_whose_sdk_call_raises_does_not_propagate():
    """Every SDK call is wrapped. The library rarely raises here — "rarely" is
    not a property a customer-facing document should rest on."""

    class Exploding:
        def update(self, **kwargs):
            raise RuntimeError("collector gone")

        def score_trace(self, **kwargs):
            raise RuntimeError("collector gone")

        def create_event(self, **kwargs):
            raise RuntimeError("collector gone")

    span = obs._SafeSpan(Exploding())
    span.update(output="x").create_event(name="e")
    obs.score(span, "gate_pass", 1.0)


def test_a_failing_flush_is_survived(monkeypatch):
    class Dead:
        def flush(self):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", Dead(), raising=False)
    obs.flush()


def test_a_failure_to_start_an_observation_still_yields_a_usable_span(monkeypatch):
    """The nastiest case: the client exists, so the call site is on the
    instrumented path, but starting the span fails. It must not get `None`."""

    class Broken:
        def start_as_current_observation(self, **kwargs):
            raise RuntimeError("transport dead")

    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", Broken(), raising=False)

    with obs.observation("node") as span:
        span.update(output="still fine")


def test_an_exception_in_the_body_is_not_swallowed(monkeypatch):
    """Tracing must be transparent in both directions. A node that fails has to
    fail the graph exactly as it would with tracing off — silently absorbing it
    would turn a failed report into a wrong one."""
    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", None, raising=False)

    with pytest.raises(ValueError, match="node failed"):
        with obs.observation("node"):
            raise ValueError("node failed")


def test_an_exception_inside_a_traced_run_is_itself(monkeypatch):
    """`trace_run` must be transparent to the body's exception.

    The bug this guards: catching around `with propagate_attributes(...):
    yield` also catches what the caller's body raised — because that exception
    is thrown back in at the yield — and yielding again from the handler makes
    a @contextmanager raise `RuntimeError: generator didn't stop after
    throw()`. A failing report would then report a tracing error instead of the
    reason it failed.
    """
    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", None, raising=False)

    with pytest.raises(ValueError, match="the real failure"):
        with obs.trace_run("report", session_id="S1"):
            raise ValueError("the real failure")


def test_a_broken_attribute_context_does_not_stop_the_run(monkeypatch):
    """Entering `propagate_attributes` may fail; the run continues untraced
    rather than not at all."""
    import app.observability as module

    def boom(**kwargs):
        raise RuntimeError("no baggage")

    monkeypatch.setattr(obs, "_resolved", True, raising=False)
    monkeypatch.setattr(obs, "_client", None, raising=False)
    monkeypatch.setattr("langfuse.propagate_attributes", boom, raising=False)

    with module.trace_run("report", session_id="S1") as root:
        root.update(output="finished anyway")


def test_a_captured_context_reattaches_on_another_thread():
    """The property that keeps one report one trace.

    LangGraph runs nodes on a `ThreadPoolExecutor`, which does not carry the
    submitting thread's `contextvars`. Without re-attaching, every node starts
    parentless and becomes the root of its own trace — one report rendering as
    a hundred fragments.

    Deliberately asserted against a real thread rather than a mock, because the
    bug IS the thread boundary: an in-thread test passes whether or not the fix
    exists. The same reason a minimal LangGraph repro was misleading — a graph
    with no checkpointer runs its node inline and nests correctly on its own.
    """
    import threading

    from opentelemetry import context as otel_context

    token = otel_context.attach(otel_context.set_value("probe", "root"))
    captured = obs.capture_context()
    otel_context.detach(token)

    seen = {}

    def worker():
        seen["without"] = otel_context.get_value("probe")
        with obs.use_context(captured):
            seen["with"] = otel_context.get_value("probe")

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert seen["without"] is None, "a fresh thread should start with no context"
    assert seen["with"] == "root", "the captured context must re-attach across threads"


def test_using_a_missing_context_is_a_no_op():
    """So a call site never has to know whether capture succeeded."""
    with obs.use_context(None):
        pass
