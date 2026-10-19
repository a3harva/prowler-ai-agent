"""The state graph: nodes, edges, and the routing that bounds the repair loop.

Fourteen nodes, sequential. There is no `Send` fan-out and no parallel branch,
which is a decision rather than an omission — `generate_report_task`'s own
docstring explains why this codebase is deliberately one colour, and parallel
branches would each need their own SQLAlchemy session since sessions are not
thread-safe. Checkpointing already delivers the property parallelism was
tempting for: a run that dies mid-investigation resumes at the pillar it was
on, not at the beginning.

**The two loops.**

`investigate_pillar` and `compose` both drain a queue and route back to
themselves. That shape is what makes each pillar its own checkpoint: LangGraph
saves state after every node, so the boundary between two pillars is a
resumable point for free. A single node iterating internally would checkpoint
once, at the end, and a run killed on the last pillar would redo all of them.

**The repair loop is bounded twice over.** `revision_count` gates re-entry at
`MAX_REVISIONS`, and the compiled graph carries a `recursion_limit` sized from
the work in front of it. The first is the real bound; the second is the
backstop for a routing bug, so a mistake here costs a failed report rather
than an unbounded spend against Vertex.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph
from langgraph.types import RetryPolicy

from app import observability
from app.agents import report_nodes as nodes
from app.agents.report_state import MAX_REVISIONS, ReportGraphState
from app.integrations.gemini import GeminiError
from app.integrations.gemini_agent import AgentModelError

logger = logging.getLogger(__name__)

# Retried at the node level, on top of the retry each integration already
# does internally. The two cover different things: the integration retries one
# request against a rate limit, this retries a whole node whose model call
# gave up. A pillar investigation is a dozen tool calls, and losing all of
# them to one exhausted quota window is worth one more attempt.
#
# Deliberately narrow. A `LedgerMutatedError` or a `KeyError` is our bug and
# retrying it just re-runs the bug at cost.
_MODEL_RETRY = RetryPolicy(max_attempts=2, retry_on=(GeminiError, AgentModelError))


def _after_investigate(state: ReportGraphState) -> str:
    """Back to the investigator while pillars remain, then onward."""
    return "investigate_pillar" if state.get("pillar_queue") else "correlate"


def _after_compose(state: ReportGraphState) -> str:
    """Back to compose while pillars remain.

    Then to `summarize` on the first pass, but straight to `verify` on a
    repair pass — unless the summary is itself a repair target. Rewriting the
    executive summary because one check's explanation was missing wastes a
    call and, worse, changes prose a reviewer may already have read.
    """
    if state.get("compose_queue"):
        return "compose"
    if state.get("revision_count", 0) == 0:
        return "summarize"
    return "summarize" if "summary" in (state.get("repair_targets") or []) else "verify"


def _after_verify(state: ReportGraphState) -> str:
    """Deterministic gates decide: repair, or hand over to the judge."""
    verification = state.get("verification") or {}
    if verification.get("passed"):
        return "critique"
    if state.get("revision_count", 0) >= MAX_REVISIONS:
        # Out of budget with gates still failing. Rendering anyway would
        # produce exactly the document the gates exist to prevent, so the run
        # ends and the Celery task marks the row failed with the gate detail.
        logger.error(
            "deep_report exhausted repairs report_id=%s failures=%s",
            state.get("report_id"),
            verification.get("failures"),
        )
        return END
    return "repair"


def _after_critique(state: ReportGraphState) -> str:
    """The judge may ask for one revision; it cannot block a report forever."""
    verdict = state.get("critique") or {}
    if verdict.get("verdict") != "revise":
        return "render"
    if state.get("revision_count", 0) >= MAX_REVISIONS:
        # Its opinion is recorded on the row either way. A model that keeps
        # asking for changes must not be able to stop a document the
        # deterministic gates have already passed.
        logger.info(
            "deep_report critique still asking for changes at the revision ceiling; "
            "rendering and recording the verdict"
        )
        return "render"
    if not (state.get("repair_targets") or []):
        # `revise` with no blocking issue names nothing to regenerate.
        return "render"
    return "repair"


def _after_repair(state: ReportGraphState) -> str:
    """Repair sets up compose work; targets that are not per-pillar go
    straight back to the node that owns them."""
    targets = state.get("repair_targets") or []
    if state.get("compose_queue"):
        return "compose"
    if "themes" in targets:
        return "correlate"
    if "reconciliation" in targets:
        return "reconcile"
    if "plan" in targets:
        return "plan_remediation"
    if "summary" in targets:
        return "summarize"
    # Nothing actionable — re-verify rather than loop.
    return "verify"


def _traced(name: str, fn, parent_context=None):
    """Wrap a node so it appears as its own span, under the run's root.

    Done here, at registration, rather than as a decorator on each of the
    twelve node functions. One place to read, one place to change, and — more
    usefully — the nodes stay plain functions of state, which is what makes
    them testable without a tracing context.

    The input recorded is the state the node was *given*, summarised; the
    output is the update it *returned*. That pairing is what makes a trace
    answer "why did this node do that", which raw state dumps do not: the
    checkpoint already holds full state, and duplicating it into every span
    would bury the delta that actually explains the run.
    """

    def traced_node(state):
        # `parent_context` is what keeps one report one trace. LangGraph runs
        # nodes on executor threads, and an OTel context does not cross a
        # thread boundary on its own — without re-attaching it here, each node
        # starts parentless and becomes its own root. See
        # `observability.capture_context` for the full shape of that failure.
        with observability.use_context(parent_context):
            with observability.observation(
                name, as_type="span", input=_state_brief(state)
            ) as span:
                update = fn(state)
                span.update(output=_update_brief(update))
                return update

    traced_node.__name__ = f"traced_{name}"
    return traced_node


# Channels worth seeing on every node, and cheap to render. `ledger` and
# `ledger_index` are deliberately excluded: they are large, identical on every
# node by construction, and their integrity is asserted by gate C8 rather than
# by being eyeballed in a trace.
_BRIEF_KEYS = (
    "report_id",
    "project_id",
    "scan_id",
    "revision_count",
    "progress",
    "pillar_queue",
    "compose_queue",
    "repair_targets",
)


def _state_brief(state) -> dict:
    try:
        brief = {k: state.get(k) for k in _BRIEF_KEYS if state.get(k) is not None}
        brief["notes"] = len(state.get("notes") or [])
        brief["ledger_digest"] = state.get("ledger_digest")
        return brief
    except Exception:  # noqa: BLE001 — tracing must never fail a node
        return {}


def _update_brief(update) -> dict:
    """What the node changed, by channel, without inlining megabytes of prose.

    A node that rewrote every pillar's analysis and one that rewrote a single
    check both return a `check_analysis` key; the sizes are what tell them
    apart, and the full text is on the report row afterwards either way.
    """
    try:
        if not isinstance(update, dict):
            return {}
        brief: dict = {}
        for key, value in update.items():
            if isinstance(value, str):
                brief[key] = value if len(value) <= 400 else f"«{len(value)} chars»"
            elif isinstance(value, (list, dict)):
                brief[key] = f"«{len(value)} items»"
            else:
                brief[key] = value
        return brief
    except Exception:  # noqa: BLE001
        return {}


def build_graph(checkpointer=None):
    """Compile the graph, optionally durable.

    **The checkpointer has to be passed to `compile()`.** `with_config
    (checkpointer=...)` looks like it would work and does not — it sets
    runnable config, not the compiled graph's saver, so the graph runs
    uncheckpointed and then dies inside Pregel on the first durability
    barrier. The only outward sign is a `UserWarning` saying no checkpointer
    is present, which is easy to read past.

    `None` is the test path: the whole graph is exercised with no Postgres and
    no `setup()`, which is what keeps the routing and gate tests fast.
    """
    # Captured here rather than passed in, because `build_graph` is called
    # from inside the task *after* its root span is open — so "the context at
    # build time" is exactly the run's root. Building outside a run (tests)
    # captures an empty context, which re-attaches harmlessly.
    parent_context = observability.capture_context()

    g = StateGraph(ReportGraphState)

    g.add_node("load_ledger", _traced("load_ledger", nodes.load_ledger, parent_context))
    # No retry policy: `recon` makes no model call, and each of its steps
    # already survives its own failure by recording it. Retrying the node would
    # re-run every step that succeeded, spending budget to re-learn what the
    # command cache would hand back anyway.
    g.add_node("recon", _traced("recon", nodes.recon, parent_context))
    g.add_node("survey", _traced("survey", nodes.survey, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("investigate_pillar", _traced("investigate_pillar", nodes.investigate_pillar, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("correlate", _traced("correlate", nodes.correlate, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("reconcile", _traced("reconcile", nodes.reconcile, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("plan_remediation", _traced("plan_remediation", nodes.plan_remediation, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("compose", _traced("compose", nodes.compose, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("summarize", _traced("summarize", nodes.summarize, parent_context), retry_policy=_MODEL_RETRY)
    g.add_node("verify", _traced("verify", nodes.verify, parent_context))
    g.add_node("critique", _traced("critique", nodes.critique, parent_context))
    g.add_node("repair", _traced("repair", nodes.repair, parent_context))
    g.add_node("render", _traced("render", nodes.render, parent_context))
    g.add_node("verify_rendered", _traced("verify_rendered", nodes.verify_rendered, parent_context))

    g.add_edge(START, "load_ledger")
    # Between the ledger and the survey, deliberately: the ledger must be frozen
    # before anything live is read (C8 checks it is unchanged afterwards), and
    # `survey` must plan against real inventory rather than guesses.
    g.add_edge("load_ledger", "recon")
    g.add_edge("recon", "survey")
    g.add_edge("survey", "investigate_pillar")
    g.add_conditional_edges(
        "investigate_pillar", _after_investigate, ["investigate_pillar", "correlate"]
    )

    # On the first pass correlate flows on to the plan. On a repair pass it
    # was re-entered for `themes` alone, and the plan depends on the themes,
    # so it flows on there too — a re-themed report whose plan still reflects
    # the old themes would be internally inconsistent in exactly the way the
    # critique is meant to catch.
    g.add_edge("correlate", "reconcile")
    # On the first pass the reconciliation flows on to the plan. On a repair
    # pass it was re-entered for C7 alone — a verdict with a bad citation —
    # and nothing the plan is built from has changed, so re-running that
    # model call would spend a call to produce the same waves.
    g.add_conditional_edges(
        "reconcile",
        lambda s: "plan_remediation" if s.get("revision_count", 0) == 0 else "verify",
        ["plan_remediation", "verify"],
    )
    g.add_conditional_edges(
        "plan_remediation",
        lambda s: "compose" if s.get("revision_count", 0) == 0 else "verify",
        ["compose", "verify"],
    )
    g.add_conditional_edges("compose", _after_compose, ["compose", "summarize", "verify"])
    g.add_edge("summarize", "verify")

    g.add_conditional_edges("verify", _after_verify, ["critique", "repair", END])
    g.add_conditional_edges("critique", _after_critique, ["render", "repair"])
    g.add_conditional_edges(
        "repair",
        _after_repair,
        ["compose", "correlate", "reconcile", "plan_remediation", "summarize", "verify"],
    )

    g.add_edge("render", "verify_rendered")
    g.add_edge("verify_rendered", END)

    return g.compile(checkpointer=checkpointer)


def recursion_limit_for(pillar_count: int) -> int:
    """A ceiling sized from the work, not a round number.

    Each pillar costs one investigate step and one compose step, a repair pass
    can recompose every pillar, and the fixed nodes plus routing hops account
    for the rest. Generous enough that a legitimate run never trips it, tight
    enough that a routing bug fails fast instead of looping against a paid API.
    """
    per_pass = max(pillar_count, 1)
    # 20 → 21 for `recon` → 22 for `reconcile`. Counted rather than absorbed
    # into the slack: the
    # constant is meant to be readable as "the fixed nodes plus routing hops",
    # and a new fixed node that does not appear in it makes the number a
    # coincidence instead of an argument.
    return 22 + per_pass * 2 + MAX_REVISIONS * (per_pass + 6)
