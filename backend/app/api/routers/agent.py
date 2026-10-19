"""The agent chat endpoints.

Thin by design: every gate lives in `services/agent.py` and
`services/agent_tools.py`, because the Celery worker is not the only thing
that must not be able to bypass them — a second router would be just as able
to forget a check as a second service function would.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user
from app.config import Settings, get_settings
from app.db import get_db
from app.schemas.agent import (
    AgentMessageResponse,
    AgentSessionCreateRequest,
    AgentSessionResponse,
    AgentTurnRequest,
    AgentTurnResponse,
    PendingActionResultResponse,
)
from app.services import agent as agent_service

router = APIRouter(prefix="/api/agent", tags=["agent"])


@router.post("/sessions", response_model=AgentSessionResponse)
def create_session_endpoint(
    body: AgentSessionCreateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    return agent_service.create_session(db, project_pk=body.project_id, current=current)


@router.get("/sessions", response_model=list[AgentSessionResponse])
def list_sessions_endpoint(
    db: Session = Depends(get_db), current: CurrentUser = Depends(get_current_user)
):
    return agent_service.list_sessions(db, current=current)


@router.get("/sessions/{session_id}", response_model=AgentSessionResponse)
def get_session_endpoint(
    session_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    return agent_service.get_session(db, session_id=session_id, current=current)


@router.get("/sessions/{session_id}/messages", response_model=list[AgentMessageResponse])
def list_messages_endpoint(
    session_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    return agent_service.list_messages(db, session_id=session_id, current=current)


@router.post("/sessions/{session_id}/messages", response_model=AgentTurnResponse)
def post_message_endpoint(
    session_id: int,
    body: AgentTurnRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    return agent_service.run_turn(
        db, session_id=session_id, message=body.message, current=current, settings=settings
    )


@router.post("/actions/{action_id}/apply", response_model=PendingActionResultResponse)
def apply_action_endpoint(
    action_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Carries the id and nothing else — deliberately. The arguments live on
    the stored row, so the change that executes is byte-for-byte the one the
    banner described."""
    return PendingActionResultResponse(
        result=agent_service.apply_pending_action(db, action_id=action_id, current=current)
    )


@router.post("/actions/{action_id}/discard", response_model=PendingActionResultResponse)
def discard_action_endpoint(
    action_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    action = agent_service.discard_pending_action(db, action_id=action_id, current=current)
    return PendingActionResultResponse(result={"status": action.status.value})
