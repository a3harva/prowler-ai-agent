"""The graph's state, its reducers, and the bounds the run is held inside.

**Everything here must be JSON-serialisable.** The checkpointer writes the
whole state to Postgres after every node, so a SQLAlchemy `Session`, a
`types.Content`, or a `Counter` in state is a run that cannot be saved. This
is a useful constraint rather than an annoying one: it forces each node to
open and close its own session instead of threading one through, which is also
what makes the nodes independently testable.

**Why the bounds are module constants and not config keys.** `app/config.py`
fails startup when any key in `CONFIG_KEYS` is missing from the resolved
backend, so adding keys here would break every existing `.env.local` until it
was hand-edited. These are also not deployment-varying values — they are
correctness bounds on a loop, exactly like `gemini_agent.MAX_TOOL_ROUNDS`,
`agent.MAX_HISTORY_MESSAGES` and `agent_tools.MAX_ROWS`, all of which are
module constants for the same reason.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

# Tool-calling rounds allowed per pillar investigation. Lower than the chat
# agent's 12: a pillar investigation has a fixed job and a model still calling
# tools on the tenth round is looping, not thorough.
MAX_INVESTIGATION_ROUNDS = 10

# How many times the graph may regenerate artifacts before giving up. Two is
# enough for the failure this loop actually sees — a compose pass that skipped
# a check, or a plan that lost one — and few enough that a model stuck in a
# consistent mistake fails the report instead of burning quota discovering it
# is stuck.
MAX_REVISIONS = 2

# Notes kept per run. Generous, because notes are short and they are the only
# thing that survives an investigation, but bounded so a runaway `remember`
# loop cannot grow the checkpoint without limit.
MAX_NOTES = 200

# The human review gate is built but not switched on — see the plan's
# "Deferred" section. `report_nodes.review_gate` reads this; flipping it to
# True is the whole change, plus the two endpoints that resume the thread.
REVIEW_GATE_ENABLED = False


def merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Reducer for the artifact maps that accumulate across a loop.

    `compose` runs once per pillar and returns only that pillar's share, so
    the default last-write-wins reducer would leave the state holding whichever
    pillar ran last. Merging is also exactly the semantics a repair pass wants:
    regenerating one check overwrites that key and leaves the rest alone.
    """
    return {**(left or {}), **(right or {})}


def cap_notes(left: list[Any], right: list[Any]) -> list[Any]:
    """Append, oldest dropped first past `MAX_NOTES`.

    Oldest-first rather than refusing new ones: the later stages of an
    investigation produce the notes `correlate` most needs, so a cap that
    silently discarded them would degrade the report in the least obvious way.
    """
    combined = (left or []) + (right or [])
    return combined[-MAX_NOTES:] if len(combined) > MAX_NOTES else combined


class ReportGraphState(TypedDict, total=False):
    """One deep report's run.

    `total=False` throughout: LangGraph merges partial updates, so a node
    returns only the channels it touched and every key is absent until some
    node sets it.
    """

    # ── inputs, set once at START and never rewritten ────────────────────────
    report_id: int
    project_pk: int
    project_id: str          # the GCP project string, for prompts
    scan_id: int
    include_muted: bool
    instructions: str | None
    # The run's own thread id, carried in state as well as in the run config.
    # `configurable` is not readable from inside a node without threading a
    # `RunnableConfig` parameter through all twelve of them, and the nodes are
    # deliberately plain functions of state. This is the key `cloud_context`
    # looks a live container up by.
    graph_thread_id: str | None

    # ── the ledger: written by load_ledger, read-only thereafter ─────────────
    ledger: dict[str, Any]
    ledger_digest: str
    ledger_index: dict[str, dict[str, Any]]

    # ── work queues, drained by the two looping nodes ────────────────────────
    pillar_queue: list[str]
    compose_queue: list[str]

    # ── live cloud state, written by recon, read-only thereafter ─────────────
    # `live_snapshot` is bounded JSON keyed by playbook step; `command_log` is
    # every attempt including the ones that failed, each with an `evidence_id`
    # the reconciliation prose must cite. `live_context_status` is one of
    # complete / partial / unavailable and is what the document's banner reads.
    live_snapshot: dict[str, Any]
    # **Appended, not replaced.** `recon` writes its eleven entries and then
    # every `investigate_pillar` pass adds the follow-ups it chose; a plain
    # channel would keep only the last writer's slice, so the evidence appendix
    # would show the playbook and none of the investigation — the half a reader
    # can already guess, and not the half they cannot. Each node returns only
    # the entries it added, which is what makes the reducer safe across a
    # resumed run.
    command_log: Annotated[list[dict[str, Any]], operator.add]
    live_context_status: str
    live_context_reason: str | None
    # Organization scope is tracked apart from the project scope above, because
    # the two fail for unrelated reasons and a denial at the organization is the
    # *expected* case — no grant is requested up front, the pipeline probes.
    # Folding it into `live_context_status` would mark almost every report
    # `partial` and drain that word of the meaning it has for project recon.
    # One of available / unavailable / not_applicable.
    org_context_status: str
    org_context_reason: str | None

    # ── session memory ───────────────────────────────────────────────────────
    strategy: str
    notes: Annotated[list[dict[str, Any]], cap_notes]

    # ── model-authored artifacts ─────────────────────────────────────────────
    check_analysis: Annotated[dict[str, dict[str, str]], merge_dicts]
    pillar_analysis: Annotated[dict[str, dict[str, str]], merge_dicts]
    themes: list[dict[str, Any]]
    # One verdict per ledger check on what live state says about it, keyed by
    # `check_id`. Merged rather than replaced for the reason the analysis maps
    # are: a repair pass regenerates this whole map today, but the reducer is
    # what makes regenerating a subset of it safe tomorrow.
    reconciliation: Annotated[dict[str, dict[str, Any]], merge_dicts]
    remediation_plan: list[dict[str, Any]]
    executive_summary: str

    # ── control ──────────────────────────────────────────────────────────────
    verification: dict[str, Any]
    critique: dict[str, Any]
    repair_targets: list[str]
    revision_count: Annotated[int, operator.add]
    progress: str

    # ── output ───────────────────────────────────────────────────────────────
    content: str
    document_problems: list[str]
