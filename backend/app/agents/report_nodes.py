"""The graph's nodes.

Each is a plain function of state. None of them holds a database session
across a return, and none of them puts a non-JSON object into state — the
checkpointer requires both, and the requirement is what keeps the nodes
independently testable.

**Where the model calls go.** Structured single-shot calls (survey, correlate,
plan, compose, summarize, critique) go through
`integrations/gemini.py::generate_json`, which is the path the standard report
already uses and which declares a response schema to the API. The one
tool-calling node goes through `integrations/gemini_agent.py`, which is the
path the chat agent uses and which carries its three Gemini tool-calling
fixes (see `agents/__init__.py`). Neither is reimplemented here; this module is orchestration.

**Failure policy.** A node that cannot get a usable answer raises. The graph
does not catch it, the Celery task does, and the report row lands `failed`
with a reason — the same all-or-nothing contract `generate_report_task`
already keeps. What the graph *does* handle is a model that answered but
answered wrongly: that is the repair loop, and it is driven by the gates
rather than by exceptions.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.agents import report_artifacts as artifacts
from app.agents import report_prompts as prompts
from app.agents.report_ledger import (
    GateFailure,
    build_index,
    digest,
    verify_artifacts,
    verify_document,
)
from app import observability
from app.agents.report_state import MAX_INVESTIGATION_ROUNDS, ReportGraphState
from app.db import get_session_factory
from app.integrations import gemini_agent
from app.integrations.gemini import generate_json
from app.services import agent_tools, report_render, reports as reports_service
from app.agents import cloud_context
from app.agents import recon_playbook
from app.agents import skills
from app.services.agent_schemas import FUNCTION_DECLARATIONS
from app.services.rbac import ALL_DEPARTMENTS

logger = logging.getLogger(__name__)


class LedgerMutatedError(RuntimeError):
    """The ledger changed after it was frozen.

    Should be unreachable. It exists because the entire count guarantee rests
    on the ledger being the same object at render time that it was at load
    time, and "should be unreachable" is not the same as checked.
    """


# ── the investigator's extra tool ────────────────────────────────────────────
# Not in `agent_tools.REGISTRY` because it is not a tool over the database —
# it writes to graph state, which only exists inside a run. Declared here and
# handled in the loop below rather than dispatched.

REMEMBER_DECLARATION: dict[str, Any] = {
    "name": "remember",
    "description": (
        "Record something you have worked out that a later stage of this report "
        "should know. These notes are the ONLY thing carried out of your "
        "investigation — the conversation itself is discarded. Record root "
        "causes, concentrations, and connections between checks, not raw counts "
        "(the report computes those itself)."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "topic": {
                "type": "STRING",
                "description": "A few words naming what this note is about.",
            },
            "note": {
                "type": "STRING",
                "description": "One or two sentences. What you concluded, and from what.",
            },
            "refs": {
                "type": "ARRAY",
                "items": {"type": "STRING"},
                "description": "The check_ids this note is about, if any.",
            },
        },
        "required": ["topic", "note"],
    },
}


RUN_CLOUD_COMMAND_DECLARATION: dict[str, Any] = {
    "name": "run_cloud_command",
    "description": (
        "Run one read-only gcloud or bq command against this report's project, to "
        "check a finding against live state. The project and the identity are "
        "supplied for you — there is no parameter for either, and passing "
        "--project or --impersonate-service-account is an error. Read the live "
        "snapshot you were given before running anything: the highest-yield "
        "calls have already been made."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "binary": {
                "type": "STRING",
                "enum": ["gcloud", "bq"],
                "description": "Which CLI to run.",
            },
            "args": {
                "type": "ARRAY",
                "items": {"type": "STRING"},
                "description": (
                    "The command's tokens, one per element — "
                    "['compute', 'instances', 'list', '--limit=10']. Not a shell "
                    "string: there is no shell, so operators do nothing and a token "
                    "containing one is refused."
                ),
            },
            "why": {
                "type": "STRING",
                "description": (
                    "One line: what you expect to learn. Kept in the report's "
                    "evidence appendix beside the command."
                ),
            },
        },
        # `why` is required deliberately. It costs a sentence and gives both the
        # trace and the customer-facing evidence appendix a human-readable
        # reason for every command run against a customer's project.
        "required": ["binary", "args", "why"],
    },
}


def read_only_declarations(*, with_cloud: bool = False) -> list[dict[str, Any]]:
    """The tool schemas the investigator is offered.

    Built by filtering `FUNCTION_DECLARATIONS` against `READ_TOOLS` rather
    than by listing names here, so a tool added to the chat agent is offered
    to the report agent automatically — and a tool that becomes a write tool
    disappears from this list the moment it joins `WRITE_TOOLS`, with no
    second place to remember to edit.
    """
    extras = [REMEMBER_DECLARATION]
    if with_cloud:
        # Offered only when a container is actually open. Declaring it against a
        # run with no live context would spend prefix bytes teaching the model a
        # tool whose every call returns "unavailable" — and would invite it to
        # keep trying, which is a worse failure than not having the tool.
        extras.append(RUN_CLOUD_COMMAND_DECLARATION)
    return [
        d for d in FUNCTION_DECLARATIONS if d["name"] in agent_tools.READ_TOOLS
    ] + extras


# ── session and context helpers ──────────────────────────────────────────────


def _tool_context(db, state: ReportGraphState) -> agent_tools.ToolContext:
    """The report agent's `ToolContext`.

    Three fields differ from a chat session's, and each is deliberate:

    - `session_id=None` — there is no `agent_sessions` row. Only `_propose`
      reads it, and `_propose` is only reachable from a write tool, which
      `dispatch_readonly` refuses.
    - `current=None` — a Celery task has no authenticated request. Only
      `_require_editor` reads it, also write-path only.
      `tests/test_report_agent_tools.py` asserts every read tool runs with it
      unset rather than leaving that as an assumption.
    - `visible_department_ids=ALL_DEPARTMENTS` — the worker runs unscoped, the
      same way `generate_report_task` reads its report row. The project
      binding still holds: `_scoped_findings_query` filters on
      `ctx.project_pk` regardless.
    """
    return agent_tools.ToolContext(
        db=db,
        session_id=None,
        project_pk=state["project_pk"],
        department_id=None,
        visible_department_ids=ALL_DEPARTMENTS,
        actor_user_id=None,
        current=None,
    )


def _settings():
    from app.config import get_settings

    return get_settings()


def _checks_for(state: ReportGraphState, pillar: str) -> list[str]:
    return [c for c, e in state["ledger_index"].items() if e["pillar"] == pillar]


def _check_brief(state: ReportGraphState, check_ids: list[str]) -> list[dict[str, Any]]:
    """What a model needs to reason about a check, and nothing more.

    Resource lists are reduced to a count for the same reason
    `report_render.pillar_user_content` reduces them: forty resource
    identifiers add tokens and hallucination surface without changing a word
    of the answer.
    """
    index = state["ledger_index"]
    return [
        {
            "check_id": c,
            "check_title": index[c]["check_title"],
            "severity": index[c]["severity"],
            "service": index[c]["service_name"],
            "affected_resource_count": index[c]["resource_count"],
        }
        for c in check_ids
    ]


# ── 1. load_ledger ───────────────────────────────────────────────────────────


def load_ledger(state: ReportGraphState) -> dict[str, Any]:
    """Build the ledger, freeze it, and plan the run around it.

    Everything downstream is shaped by what comes out of here: the pillar
    queue is the pillars that actually have findings, and the index is the set
    every gate compares against. Nothing after this node adds a check.
    """
    db = get_session_factory()()
    try:
        payload = reports_service.build_report_payload(
            db, project_id=state["project_pk"], include_muted=state["include_muted"]
        )
    finally:
        db.close()

    index = build_index(payload)
    pillars = list(payload["pillars"].keys())
    logger.info(
        "deep_report load_ledger report_id=%s pillars=%d checks=%d",
        state["report_id"],
        len(pillars),
        len(index),
    )
    return {
        "ledger": payload,
        "ledger_digest": digest(payload),
        "ledger_index": index,
        "pillar_queue": list(pillars),
        "compose_queue": list(pillars),
        "notes": [],
        "check_analysis": {},
        "pillar_analysis": {},
        "revision_count": 0,
        "progress": f"loaded {len(index)} checks across {len(pillars)} pillars",
    }


# ── 1b. recon ────────────────────────────────────────────────────────────────


MAX_SNAPSHOT_BYTES_PER_STEP = 12_000


def recon(state: ReportGraphState) -> dict[str, Any]:
    """Run the fixed playbook against the live project. **No model call.**

    Deterministic on purpose. A model asked to plan its own reconnaissance will
    sometimes not run the call that matters — and the call that matters here is
    known, because two experiments found it: one
    `asset search-all-iam-policies` surfaced three publicly invocable Cloud Run
    services that no check in the scan covers. Running it unconditionally also
    means `survey` plans against real inventory instead of guesses, and that the
    snapshot is reproducible and cacheable.

    **This node cannot fail the report.** Deep mode shipped and was correct
    before live context existed, so a project with the Cloud Asset API disabled
    must still get its report. Every outcome is a *status* the document then
    states on its face:

    | Status | Meaning |
    |---|---|
    | `complete` | every step ran |
    | `partial` | some steps failed; the failures are in the evidence appendix |
    | `unavailable` | no container — kill switch off, launch failed, no slot free |

    `unavailable` is what makes always-on honest. Without an opt-in flag there
    is no other record that live context was attempted, and a report whose recon
    failed silently would be indistinguishable from one that never had it —
    which is the worst outcome available for a document whose value is that it
    was checked against reality.
    """
    cloud = cloud_context.context_for(state.get("graph_thread_id"))
    if cloud is None:
        reason = state.get("live_context_reason") or (
            "live cloud context could not be opened for this run"
        )
        logger.warning("deep_report recon unavailable: %s", reason)
        return {
            "live_snapshot": {},
            "command_log": [],
            "live_context_status": "unavailable",
            "live_context_reason": reason,
            "progress": "live context unavailable",
        }

    snapshot: dict[str, Any] = {}
    failures: list[str] = []
    with observability.observation(
        "recon playbook", as_type="span", input={"steps": len(recon_playbook.PLAYBOOK)}
    ) as span:
        for step in recon_playbook.PLAYBOOK:
            result = cloud.run(
                binary=step.binary,
                args=step.render(state["project_id"]),
                why=step.why,
                # Charged to the run budget but to no pillar: the playbook is
                # not any pillar's work, and charging it to one would leave that
                # pillar with a smaller allowance than the others for reasons
                # nobody could see.
                pillar=None,
            )
            snapshot[step.key] = _snapshot_entry(result)
            if not result.get("ok"):
                failures.append(step.key)

        status = "complete" if not failures else "partial"
        span.update(
            output={"status": status, "failed_steps": failures},
            metadata={"commands_run": cloud.session.commands_run},
        )

    org_status, org_reason = _recon_organization(cloud, snapshot)

    logger.info(
        "deep_report recon status=%s steps=%d failed=%s org=%s",
        status, len(recon_playbook.PLAYBOOK), failures or "none", org_status,
    )
    return {
        "live_snapshot": snapshot,
        "command_log": list(cloud.log),
        "live_context_status": status,
        "live_context_reason": (
            f"{len(failures)} of {len(recon_playbook.PLAYBOOK)} playbook steps failed: "
            + ", ".join(failures)
        ) if failures else None,
        "org_context_status": org_status,
        "org_context_reason": org_reason,
        "progress": f"live context {status}",
    }


def _recon_organization(cloud, snapshot: dict[str, Any]) -> tuple[str, str | None]:
    """Probe for organization access, and use it only if it is really there.

    **No grant is requested up front.** The deferral this reverses existed
    because an org-scoped grant is a decision about every project a customer
    owns; a capability probe is a decision about nothing. It asks the API what
    this service account can already do and takes the answer.

    | Status | Meaning |
    |---|---|
    | `available` | the probe succeeded; the org playbook ran |
    | `unavailable` | the probe was denied; its stderr is the reason, verbatim |
    | `not_applicable` | the project's parent is a folder, or it has no parent |

    **The org steps never move `live_context_status`.** Denial is the expected
    case for a project where the parent organization cannot be read — and
    letting it mark every report `partial` would drain that word of meaning
    exactly when it is supposed to be a signal. Project recon and org recon are
    reported separately because they fail for unrelated reasons.

    Returns a status and a reason; writes what it learned into `snapshot`.
    """
    org_id = recon_playbook.organization_id_from(snapshot.get("project"))
    if not org_id:
        return "not_applicable", (
            "the project's parent is not an organization, so there is no "
            "organization-level policy to read"
        )

    probe = cloud.run(
        binary=recon_playbook.ORG_PROBE.binary,
        args=recon_playbook.ORG_PROBE.render(cloud.project_id, org_id),
        why=recon_playbook.ORG_PROBE.why,
        pillar=None,
    )
    snapshot[recon_playbook.ORG_PROBE.key] = _snapshot_entry(probe)
    if not probe.get("ok"):
        # Verbatim, because "the agent saw no org policies" and "the agent was
        # not allowed to look" are different facts and the reader is owed the
        # second one. This is the same rule the whole live-context design
        # follows for a failed command.
        reason = (probe.get("stderr") or probe.get("reason") or "").strip() or (
            "the organization could not be read"
        )
        logger.info("deep_report recon org unavailable: %s", reason[:200])
        return "unavailable", reason

    # Only now is the id trusted enough to scope a command with.
    cloud.organization_id = org_id
    org_failures: list[str] = []
    with observability.observation(
        "recon org playbook",
        as_type="span",
        input={"steps": len(recon_playbook.ORG_PLAYBOOK), "organization": org_id},
    ) as span:
        for step in recon_playbook.ORG_PLAYBOOK:
            result = cloud.run(
                binary=step.binary,
                args=step.render(cloud.project_id, org_id),
                why=step.why,
                pillar=None,
                org_scoped=step.org_scoped,
            )
            snapshot[step.key] = _snapshot_entry(result)
            if not result.get("ok"):
                org_failures.append(step.key)
        span.update(output={"failed_steps": org_failures})

    if org_failures:
        return "available", (
            f"{len(org_failures)} of {len(recon_playbook.ORG_PLAYBOOK)} organization "
            "steps failed: " + ", ".join(org_failures)
        )
    return "available", None


def _snapshot_entry(result: dict[str, Any]) -> dict[str, Any]:
    """What a model is given for one playbook step.

    Parsed JSON where the command produced it, so the model reasons over
    structure rather than re-parsing a string — and the raw text otherwise, so a
    step whose output is not JSON is still readable rather than dropped.

    **A failed step keeps its `stderr` verbatim and says nothing else.** The
    distinction between "there are no org policies" and "we were not allowed to
    look" is the single most important thing this node can report, and a
    flattened "failed" destroys it. The `evidence_id` is carried through so the
    reconciliation prose can cite the failure as readily as a success.
    """
    entry: dict[str, Any] = {
        "evidence_id": result.get("evidence_id"),
        "command": result.get("command"),
        "ok": bool(result.get("ok")),
    }
    if not entry["ok"]:
        entry["error"] = result.get("stderr") or result.get("reason") or "the command failed"
        return entry

    stdout = (result.get("stdout") or "")[:MAX_SNAPSHOT_BYTES_PER_STEP]
    try:
        entry["data"] = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError:
        entry["text"] = stdout
    if result.get("truncated"):
        # Flagged rather than silent, the posture `_paged` already takes: a
        # partial answer reported as complete is how a report ends up asserting
        # something nobody checked.
        entry["truncated"] = True
    return entry


# ── 2. survey ────────────────────────────────────────────────────────────────


def survey(state: ReportGraphState) -> dict[str, Any]:
    """Decide how to investigate, before investigating.

    Its output never reaches the document — it steers the pillar loop. Cheap
    (one call) and worth it: without it every pillar is investigated the same
    way regardless of what the project actually looks like.
    """
    index = state["ledger_index"]
    overview = {
        "project": state["project_id"],
        "pillars": {
            p: _check_brief(state, _checks_for(state, p)) for p in state["pillar_queue"]
        },
        "total_checks": len(index),
        "total_affected_resources": sum(e["resource_count"] for e in index.values()),
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.SURVEY + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(overview, indent=2, default=str),
        response_schema=artifacts.SURVEY_SCHEMA,
    )

    notes = [
        {"stage": "survey", "topic": n.get("topic", ""), "note": n.get("note", ""), "refs": []}
        for n in (result.get("notes") or [])
        if isinstance(n, dict)
    ]
    return {
        "strategy": (result.get("strategy") or "").strip(),
        "notes": notes,
        "progress": "planned the investigation",
    }


# ── 3. investigate_pillar (self-looping) ─────────────────────────────────────


def investigate_pillar(state: ReportGraphState) -> dict[str, Any]:
    """One pillar, investigated with the read-only tools.

    **This node is the resume point.** The graph checkpoints after every node,
    so a run killed mid-investigation restarts at the pillar it was on with
    every earlier pillar's notes intact. The tool transcript is deliberately
    local rather than in state: a resumed pillar is re-investigated from
    scratch, which is correct (its notes were never committed) and keeps
    `types.Content` — which is not JSON — out of the checkpoint.

    The loop is the chat agent's loop, reduced. It answers a whole round of
    parallel calls in ONE content, as Gemini requires; the
    round assembly is `gemini_agent.tool_response_content` verbatim rather
    than re-derived.
    """
    queue = list(state.get("pillar_queue") or [])
    if not queue:
        return {}
    pillar, rest = queue[0], queue[1:]

    check_ids = _checks_for(state, pillar)
    settings = _settings()
    cloud = cloud_context.context_for(state.get("graph_thread_id"))
    client = gemini_agent.build_client(
        settings, timeout_seconds=gemini_agent.REPORT_REQUEST_TIMEOUT_SECONDS
    )
    config = gemini_agent.build_config(
        settings=settings,
        function_declarations=read_only_declarations(with_cloud=cloud is not None),
        # **The system instruction is byte-identical on every run.** The
        # requester's free-text guidance used to be concatenated here, which
        # made the prefix vary per report and put everything behind it —
        # including the tool declarations — beyond the reach of any prefix
        # cache. It now leads the first user turn instead (below). Nothing
        # about its handling changed: it is still fenced as untrusted data and
        # still cannot widen scope. Only its position did.
        # The skill is appended to the system instruction rather than sent as a
        # user turn, because it is the most stable text in the whole request:
        # identical across every pillar of every report on every project. Put
        # anywhere later it would sit behind something that varies and lose the
        # prefix cache for itself and everything after it. Appended only when
        # the tool is actually offered, so a run without live context keeps the
        # byte-identical prefix it had before this feature existed.
        system_instruction=prompts.INVESTIGATOR
        + (("\n\n" + skills.GCLOUD) if cloud is not None else ""),
        # Explicitly the report's level, not the chat agent's. This node used
        # to inherit `low` from a default whose comment said the report path
        # did not set one — see gemini_agent.REPORT_THINKING_LEVEL.
        thinking_level=gemini_agent.REPORT_THINKING_LEVEL,
    )

    opening = {
        "pillar": pillar,
        "project": state["project_id"],
        "investigation_strategy": state.get("strategy", ""),
        "checks_in_this_pillar": _check_brief(state, check_ids),
    }
    if cloud is not None:
        # Last in the payload, after the pillar's own checks, because it is the
        # largest single block and the same on every pillar — the reverse of
        # the ordering rule for the prefix, and correct for the same reason:
        # what varies goes where it costs least.
        opening["live_snapshot"] = state.get("live_snapshot") or {}
        opening["commands_remaining_for_this_pillar"] = cloud.session.remaining_commands(
            pillar
        )
    # Ordered most-stable-first, which is the whole point of the change above:
    # the guidance is constant across every pillar of one report, the pillar
    # payload is not, so putting the guidance first leaves the longest possible
    # shared prefix between one pillar's request and the next.
    contents = [
        gemini_agent.user_content(
            prompts.user_instructions(state.get("instructions")).lstrip("\n")
            + "\n\nInvestigate this pillar. Record what you learn with `remember`.\n\n"
            + json.dumps(opening, indent=2, default=str)
        )
    ]

    collected: list[dict[str, Any]] = []
    # Where this pillar's own commands begin in the run's shared log. The
    # context is per-run and the log accumulates across pillars, so returning
    # the whole thing from every pillar would multiply the evidence appendix by
    # the pillar count.
    log_start = len(cloud.log) if cloud is not None else 0
    db = get_session_factory()()
    try:
        ctx = _tool_context(db, state)
        for _ in range(MAX_INVESTIGATION_ROUNDS):
            response = gemini_agent.generate(
                client=client, settings=settings, contents=contents, config=config
            )
            # Appended verbatim — this is the thought-signature contract, not
            # a convenience. A reconstruction drops the signature and the next
            # request is rejected.
            contents.append(gemini_agent.model_content_of(response))

            calls = gemini_agent.function_calls_of(response)
            if not calls:
                break

            round_results: list[tuple[str, str | None, dict]] = []
            for call in calls:
                args = dict(call.args or {})
                if call.name == "run_cloud_command":
                    if cloud is None:
                        result = {
                            "ok": False,
                            "reason": "live cloud context is not available for this run",
                        }
                    else:
                        result = cloud.run(
                            binary=str(args.get("binary", "")),
                            args=list(args.get("args") or []),
                            why=str(args.get("why", "")),
                            pillar=pillar,
                        )
                elif call.name == "remember":
                    note = {
                        "stage": pillar,
                        "topic": str(args.get("topic", ""))[:200],
                        "note": str(args.get("note", ""))[:1200],
                        "refs": [r for r in (args.get("refs") or []) if isinstance(r, str)],
                    }
                    collected.append(note)
                    result: dict[str, Any] = {"recorded": True, "notes_so_far": len(collected)}
                else:
                    try:
                        result = agent_tools.dispatch_readonly(ctx, name=call.name, args=args)
                    except agent_tools.ToolError as exc:
                        result = {"error": str(exc)}
                    except Exception as exc:  # noqa: BLE001
                        # `list_checks` and friends raise a bare ValueError on
                        # an unrecognised severity or status string. The chat
                        # agent survives that on its own generic handler; a
                        # node without one would die where the model would
                        # otherwise have read the error and corrected itself.
                        logger.warning(
                            "deep_report tool %s failed: %s", call.name, exc, exc_info=True
                        )
                        result = {"error": f"{call.name} failed: {exc}"}
                round_results.append((call.name, getattr(call, "id", None), result))

            # ONE content for the whole round. N contents
            # against one call turn is a hard 400 that names the part count.
            contents.append(gemini_agent.tool_response_content(round_results))
    finally:
        db.close()

    logger.info(
        "deep_report investigated pillar=%r notes=%d remaining=%d", pillar, len(collected), len(rest)
    )
    return {
        "pillar_queue": rest,
        "notes": collected,
        "command_log": list(cloud.log[log_start:]) if cloud is not None else [],
        "progress": f"investigated {pillar}",
    }


# ── 4. correlate ─────────────────────────────────────────────────────────────


def correlate(state: ReportGraphState) -> dict[str, Any]:
    """Themes across pillars — the thing a per-pillar pass cannot see."""
    index = state["ledger_index"]
    payload = {
        "project": state["project_id"],
        "notes": state.get("notes") or [],
        "checks": [
            {
                "check_id": c,
                "check_title": e["check_title"],
                "severity": e["severity"],
                "service": e["service_name"],
                "pillar": e["pillar"],
                "affected_resource_count": e["resource_count"],
            }
            for c, e in index.items()
        ],
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.CORRELATION
        + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(payload, indent=2, default=str),
        response_schema=artifacts.THEMES_SCHEMA,
    )
    themes = artifacts.coerce_themes(result, set(index))
    return {"themes": themes, "progress": f"found {len(themes)} theme(s)"}


# ── 4b. reconcile ────────────────────────────────────────────────────────────

# How much of one playbook step's output the reconciler is shown. Smaller than
# `MAX_SNAPSHOT_BYTES_PER_STEP`: this node sees every step at once, where the
# investigator saw one at a time, and the whole snapshot has to fit alongside
# the full check list in a single prompt.
MAX_RECONCILE_BYTES_PER_STEP = 4_000


def evidence_ids_of(state: ReportGraphState) -> set[str]:
    """Every citation gate C7 will accept, from the run's own command log.

    One function rather than a set comprehension at each call site, because
    `reconcile` builds the prompt from it and `verify` checks against it, and
    those two disagreeing is precisely the failure that would make C7 either
    toothless or unsatisfiable.
    """
    return {
        str(e["evidence_id"])
        for e in (state.get("command_log") or [])
        if e.get("evidence_id")
    }


def _evidence_brief(state: ReportGraphState) -> list[dict[str, Any]]:
    """The command log as the reconciler sees it: what ran, why, and what came
    back — truncated, with failures kept verbatim.

    A failed command is given to the model in full rather than summarised, for
    the reason `_snapshot_entry` keeps `stderr`: "we were not allowed to look"
    is a different fact from "there is nothing there", and it is the one the
    reader most needs the report to state.
    """
    brief: list[dict[str, Any]] = []
    for entry in state.get("command_log") or []:
        item: dict[str, Any] = {
            "evidence_id": entry.get("evidence_id"),
            "command": entry.get("command"),
            "why": entry.get("why"),
            "ok": bool(entry.get("ok")),
        }
        if entry.get("ok"):
            item["output"] = (entry.get("stdout") or "")[:MAX_RECONCILE_BYTES_PER_STEP]
        else:
            item["error"] = (
                entry.get("stderr") or entry.get("reason") or "the command failed"
            )[:1_000]
        brief.append(item)
    return brief


def reconcile(state: ReportGraphState) -> dict[str, Any]:
    """What live state says about each finding — the report's actual payoff.

    **Skips the model entirely when there is nothing to reconcile against.**
    A run whose recon was `unavailable` has an empty command log, so every
    verdict would have to be `no_evidence` and the only thing a model call
    could add is the chance of inventing a citation. `coerce_reconciliation`
    produces exactly that all-`no_evidence` map from an empty result, so the
    honest answer costs nothing and the failure mode is removed rather than
    guarded against.
    """
    index = state["ledger_index"]
    known = set(index)
    evidence_ids = evidence_ids_of(state)

    if not evidence_ids:
        logger.info(
            "deep_report reconcile skipped report_id=%s: no live evidence to reconcile against",
            state.get("report_id"),
        )
        return {
            "reconciliation": artifacts.coerce_reconciliation({}, known),
            "progress": "no live evidence to reconcile against",
        }

    payload = {
        "project": state["project_id"],
        "notes": state.get("notes") or [],
        "live_snapshot": _trimmed_snapshot(state.get("live_snapshot") or {}),
        "commands": _evidence_brief(state),
        "checks": [
            {
                "check_id": c,
                "check_title": e["check_title"],
                "severity": e["severity"],
                "service": e["service_name"],
                "pillar": e["pillar"],
                "affected_resource_count": e["resource_count"],
            }
            for c, e in index.items()
        ],
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.RECONCILIATION
        + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(payload, indent=2, default=str),
        response_schema=artifacts.RECONCILE_SCHEMA,
    )
    reconciliation = artifacts.coerce_reconciliation(result, known)
    counts: dict[str, int] = {}
    for entry in reconciliation.values():
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
    logger.info(
        "deep_report reconcile report_id=%s verdicts=%s", state.get("report_id"), counts
    )
    return {
        "reconciliation": reconciliation,
        "progress": "reconciled "
        + ", ".join(f"{n} {v}" for v, n in sorted(counts.items())),
    }


def _trimmed_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The snapshot, cut to what fits beside the full check list."""
    out: dict[str, Any] = {}
    for key, entry in snapshot.items():
        trimmed = dict(entry)
        if isinstance(trimmed.get("text"), str):
            trimmed["text"] = trimmed["text"][:MAX_RECONCILE_BYTES_PER_STEP]
        if "data" in trimmed:
            encoded = json.dumps(trimmed["data"], default=str)
            if len(encoded) > MAX_RECONCILE_BYTES_PER_STEP:
                trimmed["data"] = encoded[:MAX_RECONCILE_BYTES_PER_STEP]
                trimmed["truncated"] = True
        out[key] = trimmed
    return out


# ── 5. plan_remediation ──────────────────────────────────────────────────────


def plan_remediation(state: ReportGraphState) -> dict[str, Any]:
    """Sequencing, never commands. Gate C3 checks the partition, C6 the prose."""
    index = state["ledger_index"]
    payload = {
        "project": state["project_id"],
        "themes": state.get("themes") or [],
        "checks": [
            {
                "check_id": c,
                "check_title": e["check_title"],
                "severity": e["severity"],
                "service": e["service_name"],
                "pillar": e["pillar"],
                "affected_resource_count": e["resource_count"],
            }
            for c, e in index.items()
        ],
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.REMEDIATION_PLAN
        + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(payload, indent=2, default=str),
        response_schema=artifacts.PLAN_SCHEMA,
    )
    plan = artifacts.coerce_plan(result, set(index))
    return {"remediation_plan": plan, "progress": f"planned {len(plan)} wave(s)"}


# ── 6. compose (self-looping) ────────────────────────────────────────────────


def compose(state: ReportGraphState) -> dict[str, Any]:
    """One pillar's prose per pass, draining `compose_queue`.

    On a repair pass the queue holds only the pillars the gates named, so a
    single missing explanation costs one pillar's regeneration rather than the
    whole document's.
    """
    queue = list(state.get("compose_queue") or [])
    if not queue:
        return {}
    pillar, rest = queue[0], queue[1:]

    check_ids = _checks_for(state, pillar)
    groups = state["ledger"]["pillars"].get(pillar, [])
    payload = {
        "pillar": pillar,
        "project": state["project_id"],
        "notes": [n for n in (state.get("notes") or []) if n.get("stage") in (pillar, "survey")],
        "findings": [
            {
                "check_id": g["check_id"],
                "check_title": g["check_title"],
                "severity": g["severity"],
                "service": g.get("service_name", ""),
                "category": g.get("categories", ""),
                "description": g.get("description"),
                "risk": g.get("risk"),
                "affected_resource_count": len(g["resources"]),
                # One example, for texture. The full list is a table the
                # renderer builds; the model never sees it.
                "example_detail": (
                    g["resources"][0]["status_extended"] if g["resources"] else ""
                ),
            }
            for g in groups
        ],
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.COMPOSE.format(pillar=pillar)
        + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(payload, indent=2, default=str),
        response_schema=artifacts.COMPOSE_SCHEMA,
    )
    pillar_prose, checks = artifacts.coerce_compose(result, set(check_ids))

    return {
        "compose_queue": rest,
        "pillar_analysis": {pillar: pillar_prose},
        "check_analysis": checks,
        "progress": f"wrote {pillar}",
    }


# ── 7. summarize ─────────────────────────────────────────────────────────────


def summarize(state: ReportGraphState) -> dict[str, Any]:
    payload = {
        "pillar_narratives": {
            p: e.get("narrative", "") for p, e in (state.get("pillar_analysis") or {}).items()
        },
        "themes": [
            {"title": t["title"], "narrative": t["narrative"]} for t in (state.get("themes") or [])
        ],
        "remediation_waves": [w["label"] for w in (state.get("remediation_plan") or [])],
        "severity_counts": {
            p: dict(c) for p, c in state["ledger"]["severity_counts"].items()
        },
    }
    result = generate_json(
        settings=_settings(),
        system_instruction=prompts.SUMMARY + prompts.user_instructions(state.get("instructions")),
        user_content=json.dumps(payload, indent=2, default=str),
        response_schema=artifacts.SUMMARY_SCHEMA,
    )
    return {
        "executive_summary": (result.get("executive_summary") or "").strip(),
        "progress": "wrote the executive summary",
    }


# ── 8. verify_artifacts ──────────────────────────────────────────────────────


def _trace_gates(*, gates_run: list[str], failures: list, phase: str) -> None:
    """One event per gate, pass or fail.

    Recorded per gate rather than as one "verification" blob because that is
    the question a trace gets opened to answer: *which* gate stopped this
    report, on which check. A single event carrying a list of failures reads
    as one problem when it is usually several, and buries the check id under a
    fold.

    A passing gate is recorded too. "C4 ran and was satisfied" and "C4 never
    ran because the run died first" are very different states, and only the
    first produces an event.
    """
    by_gate: dict[str, list] = {}
    for failure in failures:
        by_gate.setdefault(failure.get("gate", "?"), []).append(failure)
    for gate in gates_run:
        _gate_event(gate=gate, found=by_gate.get(gate) or [], phase=phase)


def _gate_event(*, gate: str, found: list, phase: str) -> None:
    with observability.observation(
        f"gate {gate}",
        as_type="event",
        input={"phase": phase},
        metadata={"gate": gate, "passed": not found, "failure_count": len(found)},
        level="WARNING" if found else "DEFAULT",
    ) as span:
        if found:
            span.update(
                output=[f.get("detail") for f in found][:10],
                status_message=f"{gate} failed on {len(found)} item(s)",
            )


def verify(state: ReportGraphState) -> dict[str, Any]:
    """C1, C2, C3, C6 and C7 against the model's output.

    Runs before the critique deliberately. Deterministic checks are cheap,
    exact, and answer a different question than a judge does — there is no
    point spending a model call asking whether a document reads well when a
    gate can already prove a check is missing from it.
    """
    failures = verify_artifacts(
        index=state["ledger_index"],
        check_analysis=state.get("check_analysis") or {},
        pillar_analysis=state.get("pillar_analysis") or {},
        themes=state.get("themes") or [],
        remediation_plan=state.get("remediation_plan") or [],
        executive_summary=state.get("executive_summary") or "",
        reconciliation=state.get("reconciliation") or {},
        evidence_ids=evidence_ids_of(state),
    )
    targets = _dedupe_targets(t for f in failures for t in f.repair_targets)
    if failures:
        logger.warning(
            "deep_report gate failures report_id=%s: %s",
            state.get("report_id"),
            "; ".join(f"{f.gate}: {f.detail}" for f in failures[:5]),
        )
    failure_dicts = [f.as_dict() for f in failures]
    _trace_gates(
        gates_run=["C1", "C2", "C3", "C6", "C7"], failures=failure_dicts, phase="artifacts"
    )
    return {
        "verification": {
            "gates_run": ["C1", "C2", "C3", "C6", "C7"],
            "passed": not failures,
            "failures": failure_dicts,
            "revision": state.get("revision_count", 0),
        },
        "repair_targets": targets,
        "progress": "verified against the ledger" if not failures
        else f"{len(failures)} gate failure(s)",
    }


def _dedupe_targets(targets) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ── 9. critique ──────────────────────────────────────────────────────────────


def critique(state: ReportGraphState) -> dict[str, Any]:
    """The judge. Advisory, and it never sees the remediation commands.

    Given the artifacts rather than the rendered document on purpose: handing
    it the finished Markdown would hand it Prowler's commands to comment on,
    and the one thing this feature's design exists to prevent is a model
    getting anywhere near those. Same reasoning as the standard path's
    Markdown review, which is likewise never asked for a corrected document.
    """
    payload = {
        "project": state["project_id"],
        "executive_summary": state.get("executive_summary", ""),
        "themes": state.get("themes") or [],
        "remediation_plan": state.get("remediation_plan") or [],
        "pillar_analysis": state.get("pillar_analysis") or {},
        "checks": [
            {
                "check_id": c,
                "severity": e["severity"],
                "pillar": e["pillar"],
                "affected_resource_count": e["resource_count"],
            }
            for c, e in state["ledger_index"].items()
        ],
    }
    try:
        result = generate_json(
            settings=_settings(),
            system_instruction=prompts.CRITIQUE,
            user_content=json.dumps(payload, indent=2, default=str),
            response_schema=artifacts.CRITIQUE_SCHEMA,
        )
        verdict = artifacts.coerce_critique(result)
    except Exception as exc:  # noqa: BLE001
        # A critique that cannot run is not a reason to discard a document the
        # deterministic gates have already passed — the same call the standard
        # path makes about its advisory Markdown review.
        logger.warning("deep_report critique unavailable: %s", exc)
        verdict = {
            "verdict": "accept",
            "confidence": "low",
            "assessment": f"the critique pass could not run: {type(exc).__name__}",
            "issues": [],
        }

    targets = _dedupe_targets(
        i["target"] for i in verdict["issues"] if i["severity"] == "blocking" and i["target"]
    )
    return {
        "critique": verdict,
        "repair_targets": targets if verdict["verdict"] == "revise" else [],
        "progress": f"critique: {verdict['verdict']}",
    }


# ── 10. repair ───────────────────────────────────────────────────────────────


def repair(state: ReportGraphState) -> dict[str, Any]:
    """Turn repair targets into work, without redoing what was fine.

    `check:<id>` and `pillar:<name>` both resolve to a pillar, because compose
    is the only node that writes per-check prose and it works a pillar at a
    time. `themes`, `plan` and `summary` are handled by routing rather than
    here — the graph re-enters those nodes directly.
    """
    targets = state.get("repair_targets") or []
    index = state["ledger_index"]

    pillars: list[str] = []
    for target in targets:
        if target.startswith("pillar:"):
            pillar = target.split(":", 1)[1]
        elif target.startswith("check:"):
            check_id = target.split(":", 1)[1]
            entry = index.get(check_id)
            pillar = entry["pillar"] if entry else None
        else:
            continue
        if pillar and pillar not in pillars:
            pillars.append(pillar)

    logger.info(
        "deep_report repair revision=%d targets=%s pillars=%s",
        state.get("revision_count", 0) + 1,
        targets,
        pillars,
    )
    return {
        "compose_queue": pillars,
        "revision_count": 1,
        "progress": f"repairing {len(targets)} item(s)",
    }


# ── 11. render ───────────────────────────────────────────────────────────────


def render(state: ReportGraphState) -> dict[str, Any]:
    """Markdown from the ledger, with prose slotted in by key.

    The digest re-check is the last chance to notice that the object the
    document is built from is not the object the gates verified — a node that
    mutated the dict it was handed, or a resumed run that picked up a
    checkpoint written against a different scan.
    """
    ledger = state["ledger"]
    if digest(ledger) != state["ledger_digest"]:
        raise LedgerMutatedError(
            "the ledger changed after it was frozen — the verified counts no longer "
            "describe the document about to be rendered"
        )

    analysis = build_analysis(state)
    content = report_render.render_markdown(
        project_id=state["project_id"],
        scan_id=state["scan_id"],
        payload=ledger,
        narratives={
            p: e.get("narrative", "") for p, e in (state.get("pillar_analysis") or {}).items()
        },
        explanations={
            c: e.get("explanation", "") for c, e in (state.get("check_analysis") or {}).items()
        },
        executive_summary=state.get("executive_summary", ""),
        analysis=analysis,
        live_context=live_context_of(state),
    )
    return {"content": content, "progress": "rendered the report"}


def live_context_of(state: ReportGraphState) -> dict[str, Any]:
    """The live-context bundle both renderers and the `reports` row consume.

    One function rather than three call sites assembling the same dict, so the
    Markdown banner, the PDF and the stored row cannot disagree about what a
    run's live context was — the same invariant that keeps `build_analysis`
    single-sourced.

    Defaults to `unavailable` when `recon` never ran, which is the honest
    reading: a resumed run whose checkpoint predates this feature, or a graph
    built in a test, genuinely did not check anything.
    """
    return {
        "status": state.get("live_context_status") or "unavailable",
        "reason": state.get("live_context_reason"),
        "snapshot": state.get("live_snapshot") or {},
        "command_log": state.get("command_log") or [],
        # Defaults to `not_applicable` rather than `unavailable`: a checkpoint
        # written before the organization probe, or a graph built in a test,
        # did not probe
        # and was not denied, and reporting a denial that never happened is the
        # same class of dishonesty the banner exists to prevent.
        "organization": {
            "status": state.get("org_context_status") or "not_applicable",
            "reason": state.get("org_context_reason"),
        },
    }


def build_analysis(state: ReportGraphState) -> dict[str, Any]:
    """The narrow bundle `render_markdown` consumes.

    Only what the deep pipeline adds. The narratives and explanations stay on
    their existing parameters so `render_markdown`'s contract with the
    standard path is untouched.
    """
    return {
        "themes": state.get("themes") or [],
        "remediation_plan": state.get("remediation_plan") or [],
        "pillar_analysis": {
            p: e.get("analysis", "") for p, e in (state.get("pillar_analysis") or {}).items()
        },
        "check_context": {
            c: e.get("why_here", "") for c, e in (state.get("check_analysis") or {}).items()
        },
        "reconciliation": state.get("reconciliation") or {},
    }


# ── 12. verify_document ──────────────────────────────────────────────────────


def verify_rendered(state: ReportGraphState) -> dict[str, Any]:
    """C4, C5, C8 and C6's appendix rule against the finished Markdown, plus
    the existing structural validator. Everything here is fatal — see
    `report_ledger.verify_document`.
    """
    content = state["content"]
    failures: list[GateFailure] = verify_document(
        index=state["ledger_index"],
        payload=state["ledger"],
        content=content,
        ledger_digest=state.get("ledger_digest"),
        command_log=state.get("command_log") or [],
    )
    problems = [f"{f.gate}: {f.detail}" for f in failures]
    # The deterministic Markdown validator the standard path already runs. Its
    # job is different — it catches fences and broken tables rather than wrong
    # counts — and both must pass.
    problems += report_render.validate_markdown(content)

    verification = dict(state.get("verification") or {})
    verification["gates_run"] = list(verification.get("gates_run") or []) + [
        "C4",
        "C5",
        "C6",
        "C8",
        "markdown",
    ]
    verification["document_passed"] = not problems
    verification["document_problems"] = problems

    # C4 and C5 are fatal, so their events are the last thing a trace shows
    # before a run ends without a document. `markdown` is folded in beside them
    # because a reader chasing "why is there no report" should not have to know
    # that one of the three checks lives in a different module.
    _trace_gates(
        gates_run=["C4", "C5", "C6", "C8", "markdown"],
        failures=[f.as_dict() for f in failures],
        phase="document",
    )

    return {
        "verification": verification,
        "document_problems": problems,
        "progress": "document verified" if not problems else f"{len(problems)} document problem(s)",
    }
