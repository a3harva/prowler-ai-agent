import datetime

from pydantic import BaseModel, ConfigDict


class AgentSessionCreateRequest(BaseModel):
    # The only place a project id is ever accepted from a client, and it is
    # checked against the caller's grants before a session row exists. After
    # this, scope comes from the stored row and nothing else.
    project_id: int


class AgentSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    title: str | None
    created_at: datetime.datetime
    updated_at: datetime.datetime


class AgentMessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str
    content: str | None
    tool_name: str | None
    tool_args: dict | None
    tool_result: dict | None
    created_at: datetime.datetime


class PendingActionResponse(BaseModel):
    id: int
    tool_name: str
    summary: dict
    status: str
    expires_at: str


class AgentTurnRequest(BaseModel):
    message: str


class AgentToolCall(BaseModel):
    name: str
    args: dict
    result: dict


class AgentTurnResponse(BaseModel):
    answer: str
    tool_calls: list[AgentToolCall]
    pending_actions: list[PendingActionResponse]


class PendingActionResultResponse(BaseModel):
    result: dict
