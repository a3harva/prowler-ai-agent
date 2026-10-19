"""Session lifecycle, the tool-calling loop, and the propose/confirm gate.

The single write path rule this repo runs on holds here too: this module never
writes a finding itself. `apply_pending_action` calls
`services/findings.py::update_finding` / `mute_by_check`, which are the same
functions the human endpoints use and which already record their own audit
entries inside the same transaction.

Gate ordering is deliberate and worth not rearranging:

- `create_session` proves `viewer` on the project's department before any row
  exists, so an unauthorised user never gets a session id to work with.
- `run_turn` re-derives `ToolContext` from the **stored** session row on every
  message. Nothing about scope is carried in the request or the transcript.
- `apply_pending_action` re-proves `editor` at apply time, so a grant revoked
  between the proposal and the click loses.
"""

from __future__ import annotations

import datetime
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.agent import (
    AgentMessage,
    AgentSession,
    MessageRole,
    PendingAction,
    PendingActionStatus,
)
from app.models.finding import MuteReason
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.user_department_role import Role
from app.services import agent_schemas, agent_tools, audit, findings as findings_service
from app.services.agent_tools import ToolContext, ToolError
from app.services.errors import InvalidRequestError, NotFoundError
from app.integrations import gemini_agent
from app.services.rbac import is_department_visible, require_department_role, visible_department_ids

logger = logging.getLogger(__name__)

# Long enough to read a banner and think; short enough that a proposal cannot
# sit around until the estate has changed underneath it.
PENDING_ACTION_TTL_MINUTES = 15

# The transcript replayed to the model. Older turns are dropped oldest-first,
# never leaving a functionCall without its matching functionResponse — an
# orphaned pair is a 400.
MAX_HISTORY_MESSAGES = 60


class AgentSessionNotFoundError(NotFoundError):
    def __init__(self, session_id: int):
        super().__init__(f"no agent session with id {session_id}")


class PendingActionNotFoundError(NotFoundError):
    def __init__(self, action_id: int):
        super().__init__(f"no pending action with id {action_id}")


class PendingActionNotActionableError(InvalidRequestError):
    def __init__(self, action_id: int, status: str):
        super().__init__(f"action {action_id} is {status} and cannot be applied")


def _department_id_for_project(db: Session, project_pk: int) -> int | None:
    return db.execute(
        select(GcpOrganization.department_id)
        .join(Project, Project.gcp_organization_id == GcpOrganization.id)
        .where(Project.id == project_pk)
    ).scalar_one_or_none()


# ── sessions ─────────────────────────────────────────────────────────────────


def create_session(db: Session, *, project_pk: int, current) -> AgentSession:
    """Binds a conversation to one project, permanently.

    The permission check happens before the row is created rather than on
    first message, so an unauthorised user never holds a session id at all.
    """
    project = db.get(Project, project_pk)
    if project is None or project.deleted:
        raise InvalidRequestError(f"project {project_pk} is not onboarded")

    department_id = _department_id_for_project(db, project_pk)
    if department_id is None:
        raise InvalidRequestError(f"project {project_pk} has no owning department")
    require_department_role(db, current, department_id=department_id, minimum=Role.viewer)

    session = AgentSession(
        user_id=current.user.id, project_id=project_pk, title=project.project_id
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def get_session(db: Session, *, session_id: int, current) -> AgentSession:
    """A session belongs to the user who opened it. Not merely
    department-scoped: a conversation is personal, and another editor on the
    same department has no business reading it."""
    session = db.get(AgentSession, session_id)
    if session is None or session.user_id != current.user.id:
        raise AgentSessionNotFoundError(session_id)
    return session


def list_sessions(db: Session, *, current) -> list[AgentSession]:
    return list(
        db.execute(
            select(AgentSession)
            .where(AgentSession.user_id == current.user.id)
            .order_by(AgentSession.updated_at.desc())
            .limit(50)
        ).scalars()
    )


def list_messages(db: Session, *, session_id: int, current) -> list[AgentMessage]:
    get_session(db, session_id=session_id, current=current)
    return list(
        db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session_id)
            .order_by(AgentMessage.id)
        ).scalars()
    )


def _build_context(db: Session, *, session: AgentSession, current) -> ToolContext:
    """Scope is re-derived from the stored session row on every single turn.

    Never from the request, never from the transcript, never from anything the
    model produced. This is the function that makes §1.1's "the model cannot
    name a project" true in practice.
    """
    department_id = _department_id_for_project(db, session.project_id)
    visible = visible_department_ids(db, current)
    if not is_department_visible(department_id, visible):
        # Access revoked since the session was created.
        raise AgentSessionNotFoundError(session.id)
    return ToolContext(
        db=db,
        session_id=session.id,
        project_pk=session.project_id,
        department_id=department_id,
        visible_department_ids=visible,
        actor_user_id=current.user.id,
        current=current,
    )


# ── pending actions ──────────────────────────────────────────────────────────


def create_pending_action(
    db: Session,
    *,
    session_id: int,
    user_id: int,
    project_id: int,
    tool_name: str,
    args: dict,
    summary: dict,
) -> PendingAction:
    """Stores already-validated arguments. Called from the write tools, which
    have done their own scope and permission checks first."""
    action = PendingAction(
        session_id=session_id,
        user_id=user_id,
        project_id=project_id,
        tool_name=tool_name,
        args=args,
        summary=summary,
        status=PendingActionStatus.awaiting_confirmation,
        expires_at=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=PENDING_ACTION_TTL_MINUTES),
    )
    db.add(action)
    db.flush()
    return action


def _load_actionable(db: Session, *, action_id: int, current) -> PendingAction:
    action = db.get(PendingAction, action_id)
    if action is None or action.user_id != current.user.id:
        raise PendingActionNotFoundError(action_id)
    if action.status != PendingActionStatus.awaiting_confirmation:
        raise PendingActionNotActionableError(action_id, action.status.value)
    expires_at = action.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if expires_at < datetime.datetime.now(datetime.timezone.utc):
        action.status = PendingActionStatus.expired
        action.resolved_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        raise PendingActionNotActionableError(action_id, "expired")
    return action


def discard_pending_action(db: Session, *, action_id: int, current) -> PendingAction:
    action = _load_actionable(db, action_id=action_id, current=current)
    action.status = PendingActionStatus.discarded
    action.resolved_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(action)
    return action


def apply_pending_action(db: Session, *, action_id: int, current) -> dict:
    """The only place an agent conversation reaches a write.

    Everything it needs comes from the stored row. **Nothing is read from the
    request except the id** — that is what makes the confirmation banner
    binding rather than decorative: a tampered client cannot display one mute
    and apply another, because it never gets to say what is applied.

    The full gate stack runs again here, unconditionally:
      - the action belongs to this user (in `_load_actionable`)
      - it has not been used and has not expired
      - the caller still holds `editor` on the project's department
      - each targeted finding still belongs to the session's project
    """
    action = _load_actionable(db, action_id=action_id, current=current)

    department_id = _department_id_for_project(db, action.project_id)
    if department_id is None:
        raise PendingActionNotActionableError(action_id, "orphaned")
    # Unconditional — a revoked grant between proposal and confirmation loses.
    # Deliberately not the `if department_id is not None:` shape used by the
    # human endpoints in routers/findings.py, which is fail-open.
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    args = dict(action.args)
    tool = action.tool_name
    result: dict

    if tool == "mute_check":
        count = findings_service.mute_by_check(
            db,
            project_id=action.project_id,
            check_id=args["check_id"],
            mute_reason=MuteReason(args["mute_reason"]),
            note=args.get("note"),
            actor_user_id=current.user.id,
        )
        result = {"applied": tool, "check_id": args["check_id"], "muted_count": count}
    else:
        finding = findings_service.get_finding(
            db,
            finding_id=args["finding_id"],
            visible_department_ids=visible_department_ids(db, current),
        )
        # The proposal was scoped when it was made; re-proved here because the
        # gap between the two is exactly where a stale id would slip through.
        if finding.project_id != action.project_id:
            raise PendingActionNotActionableError(action_id, "out of scope")

        if tool == "mute_finding":
            updated = findings_service.update_finding(
                db,
                finding_id=finding.id,
                muted=True,
                mute_reason=MuteReason(args["mute_reason"]),
                note=args.get("note"),
                actor_user_id=current.user.id,
            )
        elif tool == "unmute_finding":
            updated = findings_service.update_finding(
                db,
                finding_id=finding.id,
                muted=False,
                mute_reason=None,
                note=args.get("note"),
                actor_user_id=current.user.id,
            )
        elif tool == "set_finding_note":
            # Note-only: mute state is carried through unchanged rather than
            # reasserted, so an annotation can never silently unmute.
            updated = findings_service.update_finding(
                db,
                finding_id=finding.id,
                muted=finding.muted,
                mute_reason=finding.mute_reason,
                note=args["note"],
                actor_user_id=current.user.id,
            )
        else:
            raise PendingActionNotActionableError(action_id, f"unknown tool {tool}")
        result = {
            "applied": tool,
            "finding_id": updated.id,
            "muted": updated.muted,
            "mute_reason": updated.mute_reason.value if updated.mute_reason else None,
            "note": updated.note,
        }

    action.status = PendingActionStatus.applied
    action.resolved_at = datetime.datetime.now(datetime.timezone.utc)

    # A second, agent-specific trail entry on top of the per-finding ones
    # update_finding already wrote — so the log can answer "which conversation
    # produced this mute", which the finding-level entries alone cannot.
    audit.record(
        db,
        user_id=current.user.id,
        action_type="agent.action.apply",
        target_type="agent_session",
        target_id=str(action.session_id),
        before_value={"tool": tool, "args": args},
        after_value=result,
    )
    db.commit()

    db.add(
        AgentMessage(
            session_id=action.session_id,
            role=MessageRole.tool,
            tool_name=f"{tool}:applied",
            tool_result=result,
        )
    )
    db.commit()
    return result


# ── the turn ─────────────────────────────────────────────────────────────────


def _replay_history(db: Session, *, session_id: int) -> list:
    """Rebuild the conversation for the model from stored turns.

    Only rows carrying a raw `parts` list are replayed — that list is the
    model's own response object as it arrived, thought signatures included, and
    reconstructing a turn from its display text instead would drop the
    signature and earn a 400 on the next call.
    """
    rows = list(
        db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session_id, AgentMessage.parts.isnot(None))
            .order_by(AgentMessage.id)
        ).scalars()
    )
    rows = rows[-MAX_HISTORY_MESSAGES:]
    contents = []
    for row in rows:
        role = "model" if row.role == MessageRole.assistant else "user"
        try:
            contents.append(gemini_agent.content_from_stored(role, row.parts))
        except Exception:  # noqa: BLE001 — a malformed stored turn must not kill the chat
            logger.warning("skipping unreplayable message %s", row.id)
    return contents


def run_turn(db: Session, *, session_id: int, message: str, current, settings) -> dict:
    """One user message → tool calls → one assistant answer.

    The loop is ours, not the SDK's. Every call goes through
    `agent_tools.dispatch`, which is where the session's project binding is
    injected — Automatic Function Calling would skip exactly that layer, which
    is why the model is handed schemas and never callables.

    A tool that raises `ToolError` is reported back to the model as a normal
    result rather than failing the request, so the conversation can recover
    ("that check id doesn't exist here") instead of dying on a typo.
    """
    session = get_session(db, session_id=session_id, current=current)
    ctx = _build_context(db, session=session, current=current)

    text = (message or "").strip()
    if not text:
        raise InvalidRequestError("message cannot be empty")
    if len(text) > 8000:
        raise InvalidRequestError("message is too long (8000 character limit)")

    client = gemini_agent.build_client(settings)
    config = gemini_agent.build_config(
        settings=settings,
        function_declarations=agent_schemas.FUNCTION_DECLARATIONS,
        system_instruction=agent_schemas.SYSTEM_INSTRUCTION,
    )

    contents = _replay_history(db, session_id=session_id)
    turn = gemini_agent.user_content(text)
    contents.append(turn)

    db.add(
        AgentMessage(
            session_id=session_id,
            role=MessageRole.user,
            content=text,
            parts=gemini_agent.parts_to_stored(turn),
        )
    )
    db.commit()

    tool_calls_made: list[dict] = []
    pending_action_ids: list[int] = []
    answer = ""

    for round_index in range(gemini_agent.MAX_TOOL_ROUNDS):
        response = gemini_agent.generate(
            client=client, settings=settings, contents=contents, config=config
        )
        model_content = gemini_agent.model_content_of(response)
        # Appended verbatim — this object carries the thought signatures the
        # next request has to echo back.
        contents.append(model_content)
        calls = gemini_agent.function_calls_of(response)

        db.add(
            AgentMessage(
                session_id=session_id,
                role=MessageRole.assistant,
                content=gemini_agent.text_of(response) or None,
                parts=gemini_agent.parts_to_stored(model_content),
                tool_name=",".join(c.name for c in calls) or None,
            )
        )
        db.commit()

        if not calls:
            answer = gemini_agent.text_of(response)
            break

        # Every result of this round is collected first and sent back as ONE
        # content. The API requires the number of functionResponse parts to
        # equal the number of functionCall parts in the turn being answered,
        # so a model that asked for two things in one turn must be answered
        # once with two parts — not twice with one part each, which is a 400.
        round_results: list[tuple[str, str | None, dict]] = []
        for call in calls:
            args = dict(call.args or {})
            try:
                result = agent_tools.dispatch(ctx, name=call.name, args=args)
                if result.get("status") == "awaiting_confirmation":
                    pending_action_ids.append(result["action_id"])
            except ToolError as exc:
                result = {"error": str(exc)}
            except Exception as exc:  # noqa: BLE001
                logger.exception("tool %s failed", call.name)
                result = {"error": f"{call.name} failed: {exc}"}

            tool_calls_made.append({"name": call.name, "args": args, "result": result})
            # Display row, one per call — what the transcript UI renders. Kept
            # separate from the replay row below, which is one per round.
            db.add(
                AgentMessage(
                    session_id=session_id,
                    role=MessageRole.tool,
                    tool_name=call.name,
                    tool_args=args,
                    tool_result=result,
                )
            )
            round_results.append((call.name, getattr(call, "id", None), result))

        tool_content = gemini_agent.tool_response_content(round_results)
        contents.append(tool_content)
        # One replay row per round, matching the one content just appended.
        # Storing one row per call would reproduce the same 400 on the next
        # turn, when `_replay_history` rebuilt a content from each row.
        db.add(
            AgentMessage(
                session_id=session_id,
                role=MessageRole.user,
                parts=gemini_agent.parts_to_stored(tool_content),
            )
        )
        db.commit()
    else:
        # Hit the round ceiling without the model ever answering. Surfaced
        # rather than absorbed — a silent truncation here would read to the
        # user as the assistant simply having nothing to say.
        answer = (
            "I wasn't able to finish this one — I kept needing more data and hit "
            "my tool-call limit for a single question. Try narrowing it down."
        )

    if not answer:
        answer = "I don't have an answer for that."

    db.add(AgentMessage(session_id=session_id, role=MessageRole.assistant, content=answer))
    session.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()

    pending = (
        list(
            db.execute(
                select(PendingAction).where(PendingAction.id.in_(pending_action_ids))
            ).scalars()
        )
        if pending_action_ids
        else []
    )
    return {
        "answer": answer,
        "tool_calls": tool_calls_made,
        "pending_actions": [
            {
                "id": a.id,
                "tool_name": a.tool_name,
                "summary": a.summary,
                "status": a.status.value,
                "expires_at": a.expires_at.isoformat(),
            }
            for a in pending
        ],
    }
