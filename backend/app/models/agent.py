"""Chat sessions, their transcripts, and the pending writes they propose.

Three tables, one rule between them: **the project binding lives on the
session and nowhere else.** `agent_sessions.project_id` is written once at
creation and never updated, and every tool call derives its scope from that
row rather than from anything the model or the client said. Switching project
means a new session — see `services/agent_tools.py` for why the model is
never handed a `project_id` argument at all.

`pending_actions` is the propose-then-confirm gate. A write tool does not
write; it stores its already-validated arguments here and returns an id. The
confirm request carries only that id, so what executes is byte-for-byte what
the user was shown — if the arguments travelled back with the confirmation, a
tampered client could display one mute and apply another, and the banner
would be decoration.
"""

import datetime
import enum

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class MessageRole(str, enum.Enum):
    user = "user"
    assistant = "assistant"
    # A tool result, stored as its own row rather than folded into the
    # assistant turn, so the transcript can be replayed to the model exactly
    # as it happened and so a tool call is individually auditable.
    tool = "tool"


class PendingActionStatus(str, enum.Enum):
    awaiting_confirmation = "awaiting_confirmation"
    applied = "applied"
    discarded = "discarded"
    expired = "expired"


class AgentSession(Base):
    __tablename__ = "agent_sessions"
    __table_args__ = (
        # Declared here as well as in the migration: an index that exists only
        # in a migration reads as an orphan to the next autogenerate.
        Index("ix_agent_sessions_user_id", "user_id"),
        Index("ix_agent_sessions_project_id", "project_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    # Immutable after creation. The whole access model rests on this.
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class AgentMessage(Base):
    __tablename__ = "agent_messages"
    __table_args__ = (Index("ix_agent_messages_session_id", "session_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[MessageRole] = mapped_column(
        Enum(MessageRole, name="agent_message_role"), nullable=False
    )
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The model's own turn object, stored verbatim. Gemini 3 returns an
    # encrypted `thought_signature` on function calls and **rejects a follow-up
    # request that does not pass it back** (a hard 400), so replaying a
    # conversation means replaying the response object as it arrived rather
    # than a prettified reconstruction of it. Keeping the raw part list is what
    # makes that possible — see integrations/gemini_agent.py.
    parts: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Denormalised for the transcript UI, which renders a tool call as its own
    # card without needing to parse `parts`.
    tool_name: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_args: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    tool_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PendingAction(Base):
    """A proposed write, held until a human confirms it.

    `args` holds the **already-validated** tool arguments. Nothing from the
    confirm request is merged into them; the request carries an id and nothing
    else. That is the entire reason this table exists rather than the frontend
    simply calling the mute endpoint when the user clicks Confirm.
    """

    __tablename__ = "pending_actions"
    __table_args__ = (Index("ix_pending_actions_session_id", "session_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False
    )
    # Carried alongside the session's own user so the apply path can assert
    # both without a join, and so a session row changing hands could never
    # silently re-point somebody else's pending write.
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False)

    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    args: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # What the banner shows: target, reason, note, affected count, sample
    # resources. Built at proposal time from the same validated args, so the
    # description and the effect cannot drift apart.
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False)

    status: Mapped[PendingActionStatus] = mapped_column(
        Enum(PendingActionStatus, name="pending_action_status"), nullable=False
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
