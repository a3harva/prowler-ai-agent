import datetime

from pydantic import BaseModel


class AuditLogEntryResponse(BaseModel):
    id: int
    user_id: int
    actor_email: str
    actor_name: str
    action_type: str
    target_type: str
    target_id: str
    before_value: dict | None
    after_value: dict | None
    timestamp: datetime.datetime
