"""The deep-report graph, with Gemini stubbed out.

Two things are proved here that nothing else can prove:

1. **The read-only gate holds.** Not by reading the code, but by running every
   tool the report agent is offered against the exact `ToolContext` the worker
   builds — one with no authenticated user and no agent session — and by
   asking `dispatch_readonly` for a write tool and watching it refuse.
2. **The repair loop converges.** A model that skips a check on its first pass
   and supplies it on the second must produce a complete document, and one
   that never supplies it must fail the report rather than render an
   incomplete one.

The model is replaced at the seam each node calls — `generate_json` for the
structured nodes, the SDK wrapper for the tool loop — so the graph's routing,
its state reducers and its gates are exercised for real while nothing leaves
the machine.
"""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

import pytest

from app.agents import report_nodes
from app.agents.report_graph import build_graph, recursion_limit_for
from app.agents.report_state import MAX_REVISIONS
from app.models.finding import FindingStatus, Severity
from app.services import agent_tools
from app.services.agent_tools import READ_TOOLS, WRITE_TOOLS, ToolError
from app.services.rbac import ALL_DEPARTMENTS

from tests.test_reports import _add_finding, _make_project, _make_scan, _seed_mapping


SECURITY = "Security, Privacy & Compliance"
OPS = "Operational Excellence"


@pytest.fixture()
def seeded(db_session):
    """A project with findings in two pillars."""
    _seed_mapping(db_session)
    project = _make_project(db_session, project_id="deep-proj", freshservice_id="950")
    scan, user = _make_scan(db_session, project)
    _add_finding(db_session, project, scan, check_id="iam_broad", resource_uid="r1",
                 categories="identity-access", severity=Severity.critical)
    _add_finding(db_session, project, scan, check_id="iam_broad", resource_uid="r2",
                 categories="identity-access", severity=Severity.critical)
    _add_finding(db_session, project, scan, check_id="bucket_open", resource_uid="r3",
                 categories="internet-exposed", severity=Severity.high)
    _add_finding(db_session, project, scan, check_id="logs_off", resource_uid="r4",
                 categories="logging", severity=Severity.medium)
    db_session.commit()
    return {"project": project, "scan": scan, "user": user}


# ── the read-only gate ───────────────────────────────────────────────────────


def test_the_report_agent_is_offered_no_write_tool():
    names = {d["name"] for d in report_nodes.read_only_declarations()}
    assert not (names & WRITE_TOOLS)
    assert "remember" in names, "the note-taking tool must be offered"
    # Every read tool, so a tool added to the chat agent reaches the report
    # agent without a second list to remember to edit.
    assert READ_TOOLS <= names


@pytest.mark.parametrize("tool_name", sorted(WRITE_TOOLS))
def test_dispatch_readonly_refuses_every_write_tool(db_session, seeded, tool_name):
    ctx = _worker_context(db_session, seeded)
    with pytest.raises(ToolError, match="not available while generating a report"):
        agent_tools.dispatch_readonly(ctx, name=tool_name, args={})


def _worker_context(db_session, seeded):
    """Exactly what `report_nodes._tool_context` builds — no user, no session."""
    return agent_tools.ToolContext(
        db=db_session,
        session_id=None,
        project_pk=seeded["project"].id,
        department_id=None,
        visible_department_ids=ALL_DEPARTMENTS,
        actor_user_id=None,
        current=None,
    )


def test_every_read_tool_runs_without_a_current_user(db_session, seeded):
    """The worker has no authenticated request, so `ctx.current` is None.

    That is only safe because nothing on the read path dereferences it. This
    asserts it rather than trusting it — a read tool that starts calling
    `require_department_role` would otherwise fail in production, inside a
    Celery task, on a customer's report.
    """
    ctx = _worker_context(db_session, seeded)
    required_args = {
        "get_finding": {"finding_id": _a_finding_id(db_session, seeded)},
        "list_check_resources": {"check_id": "iam_broad"},
        "get_requirements_for_check": {"check_id": "iam_broad"},
        "get_compliance_posture": {"framework": "CIS", "framework_name": "CIS 2.0"},
    }
    for name in sorted(READ_TOOLS):
        result = agent_tools.dispatch_readonly(ctx, name=name, args=required_args.get(name, {}))
        assert isinstance(result, dict), f"{name} returned {type(result)}"


def _a_finding_id(db_session, seeded):
    from sqlalchemy import select

    from app.models.finding import Finding

    return db_session.execute(
        select(Finding.id).where(Finding.project_id == seeded["project"].id).limit(1)
    ).scalar_one()


def test_a_bad_enum_string_raises_out_of_the_tool_itself(db_session, seeded):
    """`list_checks` does an unguarded `Severity(s)`, so a severity the model
    invents raises a bare ValueError rather than a `ToolError`.

    Recorded here because it is the reason the investigation loop needs a
    catch-all beyond `ToolError` —
    `test_the_investigation_loop_survives_a_tool_that_raises` covers the
    other half.
    """
    ctx = _worker_context(db_session, seeded)
    with pytest.raises(ValueError):
        agent_tools.dispatch_readonly(ctx, name="list_checks", args={"severity": ["banana"]})


# ── the investigation loop ───────────────────────────────────────────────────


class _Call:
    def __init__(self, name, args, call_id="c0"):
        self.name = name
        self.args = args
        self.id = call_id


class _Response:
    """The shape `gemini_agent`'s helpers read off a real SDK response."""

    def __init__(self, calls=(), text=""):
        self._calls = list(calls)
        self._text = text

    @property
    def function_calls(self):
        return self._calls or None

    @property
    def candidates(self):
        return [type("C", (), {"content": {"role": "model", "parts": []}})()]


def _install_loop_stubs(monkeypatch, responses):
    """Replace the SDK seam, leaving the loop itself real."""
    # **kwargs, not a fixed arity: the report path passes its own
    # `timeout_seconds` because it is not a chat turn, and a stub that
    # pins the signature turns a deliberate parameter into a test failure.
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.build_client", lambda s, **kwargs: object()
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.build_config",
        lambda **kwargs: object(),
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.model_content_of", lambda r: {"role": "model"}
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.tool_response_content",
        lambda results: {"role": "user", "results": results},
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.user_content", lambda t: {"role": "user"}
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.function_calls_of",
        lambda r: list(getattr(r, "function_calls", None) or []),
    )
    seq = iter(responses)
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.generate",
        lambda **kwargs: next(seq),
    )


def _investigation_state(db_session, seeded, monkeypatch):
    from app.agents.report_nodes import load_ledger

    monkeypatch.setattr(
        "app.agents.report_nodes.get_session_factory",
        lambda: lambda: _NonClosing(db_session),
    )
    state = {
        "report_id": 1,
        "project_pk": seeded["project"].id,
        "project_id": seeded["project"].project_id,
        "scan_id": seeded["scan"].id,
        "include_muted": False,
        "instructions": None,
    }
    return {**state, **load_ledger(state), "strategy": "look at identity"}


def test_the_investigation_loop_records_notes_and_drains_the_queue(
    db_session, seeded, monkeypatch
):
    state = _investigation_state(db_session, seeded, monkeypatch)
    _install_loop_stubs(
        monkeypatch,
        [
            _Response([_Call("remember", {"topic": "identity", "note": "one binding explains both",
                                          "refs": ["iam_broad"]})]),
            _Response([]),
        ],
    )

    update = report_nodes.investigate_pillar(state)

    assert len(update["notes"]) == 1
    assert update["notes"][0]["topic"] == "identity"
    assert update["notes"][0]["stage"] == state["pillar_queue"][0]
    assert update["pillar_queue"] == state["pillar_queue"][1:]


def test_the_investigation_loop_survives_a_tool_that_raises(db_session, seeded, monkeypatch):
    """A ValueError out of a tool must reach the model as a result, not kill
    the node. The model then gets a chance to correct itself, which is the
    whole reason tool errors are data rather than exceptions."""
    state = _investigation_state(db_session, seeded, monkeypatch)
    captured = {}

    _install_loop_stubs(
        monkeypatch,
        [
            _Response([_Call("list_checks", {"severity": ["banana"]})]),
            _Response([]),
        ],
    )
    real = report_nodes.gemini_agent.tool_response_content
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.tool_response_content",
        lambda results: captured.setdefault("results", results),
    )

    update = report_nodes.investigate_pillar(state)

    assert "error" in captured["results"][0][2], "the failure must reach the model as a result"
    assert update["pillar_queue"] == state["pillar_queue"][1:], "the node must still complete"


def test_the_investigation_loop_refuses_a_write_tool(db_session, seeded, monkeypatch):
    """Belt and braces: even if a write tool were somehow declared, the
    dispatcher refuses it and the refusal reaches the model as a result."""
    state = _investigation_state(db_session, seeded, monkeypatch)
    captured = {}

    _install_loop_stubs(
        monkeypatch,
        [
            _Response([_Call("mute_check", {"check_id": "iam_broad", "mute_reason": "risk_accepted"})]),
            _Response([]),
        ],
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.tool_response_content",
        lambda results: captured.setdefault("results", results),
    )

    report_nodes.investigate_pillar(state)

    assert "not available while generating a report" in captured["results"][0][2]["error"]


def test_the_loop_answers_a_parallel_round_with_one_content(db_session, seeded, monkeypatch):
    """Gemini tool-calling contract: a turn carrying several function calls
    must be answered by ONE content carrying all their results. N contents
    against one call turn is a hard 400."""
    state = _investigation_state(db_session, seeded, monkeypatch)
    rounds = []

    _install_loop_stubs(
        monkeypatch,
        [
            _Response([
                _Call("get_findings_summary", {}, "a"),
                _Call("list_services", {}, "b"),
                _Call("remember", {"topic": "t", "note": "n"}, "c"),
            ]),
            _Response([]),
        ],
    )
    monkeypatch.setattr(
        "app.agents.report_nodes.gemini_agent.tool_response_content",
        lambda results: rounds.append(results) or {"role": "user"},
    )

    report_nodes.investigate_pillar(state)

    assert len(rounds) == 1, "one round of calls must produce exactly one content"
    assert len(rounds[0]) == 3, "every call in the round must be answered in it"


# ── the graph ────────────────────────────────────────────────────────────────


class FakeModel:
    """Stands in for Gemini at the `generate_json` seam.

    Dispatches on a marker in the system instruction rather than on call
    order, so a change to the graph's routing does not silently reshuffle
    which canned answer each node gets.
    """

    def __init__(self, *, skip_checks=(), skip_forever=False, critique_verdict="accept"):
        self.skip_checks = set(skip_checks)
        self.skip_forever = skip_forever
        self.critique_verdict = critique_verdict
        self.calls: list[str] = []
        self._composed = 0

    def __call__(self, *, settings, system_instruction, user_content, response_schema, **kwargs):
        import json

        payload = json.loads(user_content)

        if "planning a GCP security assessment" in system_instruction:
            self.calls.append("survey")
            return {"strategy": "Look at identity first.", "focus_areas": ["iam"],
                    "notes": [{"topic": "identity", "note": "iam_broad spans two resources."}]}

        if "finding the themes" in system_instruction:
            self.calls.append("correlate")
            return {"themes": [{
                "title": "One binding, several exposures",
                "narrative": "The same permissive grant explains both security findings.",
                "refs": ["iam_broad", "bucket_open"],
            }]}

        if "sequencing the remediation work" in system_instruction:
            self.calls.append("plan")
            return {"waves": [
                {"label": "Close the identity gaps", "rationale": "Everything else assumes this.",
                 "refs": ["iam_broad", "bucket_open"]},
                {"label": "Restore audit coverage", "rationale": "Meaningful once access is fixed.",
                 "refs": ["logs_off"]},
            ]}

        if "executive summary" in system_instruction:
            self.calls.append("summary")
            return {"executive_summary": "Two identity issues dominate this project's posture."}

        if "reviewing a GCP security assessment" in system_instruction:
            self.calls.append("critique")
            return {"verdict": self.critique_verdict, "confidence": "high",
                    "assessment": "The sequencing is defensible.",
                    "issues": ([{"severity": "blocking", "target": "plan",
                                 "problem": "wave two is under-scoped"}]
                               if self.critique_verdict == "revise" else [])}

        # compose
        self.calls.append("compose")
        self._composed += 1
        checks = [f["check_id"] for f in payload["findings"]]
        skipping = self.skip_checks if (self.skip_forever or self._composed <= 2) else set()
        return {
            "pillar_narrative": f"Narrative for {payload['pillar']}.",
            "pillar_analysis": f"Analysis for {payload['pillar']}.",
            "findings": [
                {"check_id": c, "explanation": f"What {c} means.", "why_here": f"Why {c} here."}
                for c in checks
                if c not in skipping
            ],
        }


@pytest.fixture()
def stub_model(monkeypatch):
    def _install(model):
        monkeypatch.setattr("app.agents.report_nodes.generate_json", model)
        # The investigation loop is not what these tests exercise; it is
        # replaced wholesale so the graph's routing and gates are what is
        # under test.
        monkeypatch.setattr(
            "app.agents.report_nodes.investigate_pillar",
            lambda state: {
                "pillar_queue": list(state.get("pillar_queue") or [])[1:],
                "notes": [{"stage": (state.get("pillar_queue") or ["?"])[0],
                           "topic": "stub", "note": "investigated", "refs": []}],
            },
        )
        return model

    return _install


def _run(db_session, seeded, model, stub_model, monkeypatch):
    stub_model(model)
    # Nodes open their own session from the factory; in a test they must join
    # the fixture's transaction or they would see an empty database.
    monkeypatch.setattr(
        "app.agents.report_nodes.get_session_factory",
        lambda: lambda: _NonClosing(db_session),
    )
    graph = build_graph()
    return graph.invoke(
        {
            "report_id": 1,
            "project_pk": seeded["project"].id,
            "project_id": seeded["project"].project_id,
            "scan_id": seeded["scan"].id,
            "include_muted": False,
            "instructions": None,
        },
        config={"recursion_limit": recursion_limit_for(6)},
    )


class _NonClosing:
    """The fixture session, with `close()` disarmed.

    Nodes close the session they open, which is right in production and fatal
    in a test — the fixture's transaction has to outlive every node.
    """

    def __init__(self, session):
        self._session = session

    def __getattr__(self, name):
        return getattr(self._session, name)

    def close(self):
        return None


def test_a_clean_run_produces_a_verified_document(db_session, seeded, stub_model, monkeypatch):
    final = _run(db_session, seeded, FakeModel(), stub_model, monkeypatch)

    assert final["verification"]["passed"] is True
    assert final["document_problems"] == []
    assert final["critique"]["verdict"] == "accept"

    content = final["content"]
    assert "## Key Themes" in content
    assert "## Remediation Plan" in content
    assert "**Why this matters here**" in content
    # Every ledger check has a section, and no others.
    for check_id in final["ledger_index"]:
        assert f"`{check_id}` · " in content


def test_the_ledger_drives_the_document_not_the_model(db_session, seeded, stub_model, monkeypatch):
    final = _run(db_session, seeded, FakeModel(), stub_model, monkeypatch)

    assert set(final["ledger_index"]) == {"iam_broad", "bucket_open", "logs_off"}
    assert final["ledger_index"]["iam_broad"]["resource_count"] == 2
    # The rendered resource table must agree with the database, not with
    # anything the model said.
    assert final["content"].count("| `r1` |") == 1
    assert final["content"].count("| `r2` |") == 1


def test_a_skipped_check_is_repaired_rather_than_shipped(
    db_session, seeded, stub_model, monkeypatch
):
    """The failure this whole design exists to catch: a model that quietly
    drops a finding. Gate C1 must notice and the graph must regenerate."""
    model = FakeModel(skip_checks={"bucket_open"})
    final = _run(db_session, seeded, model, stub_model, monkeypatch)

    assert final["revision_count"] >= 1, "the graph must have repaired"
    assert final["verification"]["passed"] is True
    assert "bucket_open" in final["check_analysis"]
    assert "**What this means**" in final["content"]


def test_a_check_that_is_never_supplied_fails_the_report(
    db_session, seeded, stub_model, monkeypatch
):
    """The other half: repair is bounded. A model stuck in a consistent
    mistake must fail the report, not render an incomplete one."""
    model = FakeModel(skip_checks={"bucket_open"}, skip_forever=True)
    final = _run(db_session, seeded, model, stub_model, monkeypatch)

    assert final["verification"]["passed"] is False
    assert final["revision_count"] == MAX_REVISIONS
    assert "content" not in final, "a document must not be rendered on failed gates"
    gates = {f["gate"] for f in final["verification"]["failures"]}
    assert "C1" in gates


def test_a_critique_asking_for_changes_triggers_one_revision(
    db_session, seeded, stub_model, monkeypatch
):
    model = FakeModel(critique_verdict="revise")
    final = _run(db_session, seeded, model, stub_model, monkeypatch)

    # It re-plans, re-verifies, and still renders — the critique is advisory
    # and must not be able to block a document the gates have passed.
    assert final["revision_count"] >= 1
    assert final["content"]
    assert final["critique"]["verdict"] == "revise"
    assert model.calls.count("plan") >= 2


def test_the_digest_catches_a_mutated_ledger(db_session, seeded, stub_model, monkeypatch):
    from app.agents.report_nodes import LedgerMutatedError, render

    final = _run(db_session, seeded, FakeModel(), stub_model, monkeypatch)
    tampered = dict(final)
    tampered["ledger"] = {**final["ledger"], "skipped_finding_count": 99}

    with pytest.raises(LedgerMutatedError):
        render(tampered)


# ── resume ───────────────────────────────────────────────────────────────────


def test_resuming_takes_none_not_the_input():
    """The bug this locks in cost a run to find.

    `graph.invoke(initial, config)` on a thread that stopped mid-run does NOT
    resume — it restarts from START and re-runs every node that already
    succeeded. Only `graph.invoke(None, config)` continues. On the report
    graph that is the difference between re-investigating every pillar and
    skipping straight to the node that failed, which is the entire reason the
    checkpointer is here.

    Asserted on a toy graph rather than the real one so it stays fast and
    tests the LangGraph semantics rather than our nodes. If a future LangGraph
    changes this behaviour, this test says so before a report does.
    """
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph

    def first(_s):
        return {"ran": ["first"]}

    def second(s):
        if s.get("explode"):
            raise RuntimeError("simulated outage")
        return {"ran": ["second"]}

    builder = StateGraph(_ResumeState)
    builder.add_node("first", first)
    builder.add_node("second", second)
    builder.add_edge(START, "first")
    builder.add_edge("first", "second")
    builder.add_edge("second", END)
    graph = builder.compile(checkpointer=InMemorySaver())

    config = {"configurable": {"thread_id": "resume-test"}}
    with pytest.raises(RuntimeError):
        graph.invoke({"ran": [], "explode": True}, config, durability="sync")

    snapshot = graph.get_state(config)
    assert snapshot.next == ("second",), "an interrupted run must report pending work"
    assert snapshot.values["ran"] == ["first"]

    graph.update_state(config, {"explode": False})
    final = graph.invoke(None, config, durability="sync")

    assert final["ran"] == ["first", "second"], (
        "resuming with None must continue, not re-run the completed node"
    )


def test_a_fresh_thread_reports_no_pending_work():
    """The other half of the branch in `generate_deep_report_task`: a thread
    that has never run must take the input, not None."""
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(_FreshState)
    builder.add_node("only", lambda _s: {"value": "done"})
    builder.add_edge(START, "only")
    builder.add_edge("only", END)
    graph = builder.compile(checkpointer=InMemorySaver())

    config = {"configurable": {"thread_id": "never-run"}}
    assert graph.get_state(config).next == (), "a fresh thread has nothing pending"


class _ResumeState(TypedDict, total=False):
    """Defined at module scope, not inside the test.

    `TypedDict` resolves its annotations against the *module* globals, so a
    class declared inside a function whose types were imported locally raises
    `NameError: name 'Annotated' is not defined` at class-creation time.
    """

    ran: Annotated[list, operator.add]
    explode: bool


class _FreshState(TypedDict, total=False):
    value: str


def test_one_run_stays_one_trace_across_the_whole_graph(monkeypatch):
    """Every node must execute inside the run's context, not a fresh one.

    LangGraph dispatches nodes through a `ThreadPoolExecutor`, and an
    OpenTelemetry context lives in a `contextvar`, which does not cross a
    thread boundary. Without `build_graph` capturing the context and each node
    wrapper re-attaching it, every node starts parentless and becomes the root
    of its own trace — a single report arriving as a hundred unrelated
    fragments, each holding one node.

    Two things make that failure hard to catch by inspection, and both are why
    this test exists:

    - spans nest correctly *inside* a node, so the instrumentation looks right
      everywhere you look;
    - a trivial graph compiled with **no checkpointer** runs its node inline on
      the calling thread and nests fine, so a minimal reproduction disproves
      the bug rather than confirming it. Hence a checkpointer here.

    Asserted on the context itself rather than on span ids, so the test does
    not need Langfuse configured — the suite runs with tracing off.
    """
    from unittest.mock import patch

    from langgraph.checkpoint.memory import MemorySaver
    from opentelemetry import context as otel_context

    from app.agents import report_graph

    seen: dict[str, object] = {}

    def stub(name):
        def fn(state):
            seen[name] = otel_context.get_value("run-probe")
            return {"progress": name}

        return fn

    node_names = [
        "load_ledger", "survey", "investigate_pillar", "correlate", "plan_remediation",
        "compose", "summarize", "verify", "critique", "repair", "render", "verify_rendered",
    ]
    patches = [patch.object(report_nodes, n, stub(n)) for n in node_names]
    for p in patches:
        p.start()
    try:
        token = otel_context.attach(otel_context.set_value("run-probe", "the-one-run"))
        try:
            # Built inside the context, exactly as the Celery task builds it
            # inside its root span.
            graph = report_graph.build_graph(MemorySaver())
        finally:
            otel_context.detach(token)

        graph.invoke(
            {
                "report_id": 1, "pillar_queue": [], "compose_queue": [],
                "verification": {"passed": True}, "ledger_index": {}, "ledger": {},
                "content": "x", "revision_count": 0,
            },
            config={"configurable": {"thread_id": "trace-nesting"}, "recursion_limit": 40},
        )
    finally:
        for p in patches:
            p.stop()

    assert seen, "no node ran; the probe would pass vacuously"
    detached = [n for n, v in seen.items() if v != "the-one-run"]
    assert not detached, f"these nodes ran outside the run's context: {detached}"


def test_a_run_with_no_live_context_still_produces_a_document(
    db_session, seeded, stub_model, monkeypatch
):
    """The failure policy, proven through the whole graph rather than the node.

    Nothing registers a `CloudContext` here, which is the same state a run has
    when the kill switch is off, when the container cannot start, when Docker is
    unreachable, and when every slot is busy — all four verified to yield `None`
    rather than raise. Deep mode shipped and was correct before live context
    existed, so a project with the Cloud Asset API disabled must still get its
    report: the run degrades and says so, and never fails.
    """
    from app.services import report_render

    final = _run(db_session, seeded, FakeModel(), stub_model, monkeypatch)

    assert final["content"]
    assert final["live_context_status"] == "unavailable"
    assert final["live_snapshot"] == {}
    assert final["command_log"] == []

    # And the reader is told, on the face of the document, above the summary.
    banner = report_render.live_context_note(
        {"status": final["live_context_status"], "reason": final.get("live_context_reason")}
    )
    assert "Live context unavailable" in banner
    assert "Live context unavailable" in final["content"]
