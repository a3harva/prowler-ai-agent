import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, require_admin
from app.db import get_db
from app.schemas.audit import AuditLogEntryResponse
from app.services.audit import list_audit_log

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogEntryResponse])
def list_audit_log_endpoint(
    user_id: int | None = None,
    action_type: str | None = None,
    target_type: str | None = None,
    date_from: datetime.datetime | None = None,
    date_to: datetime.datetime | None = None,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    rows = list_audit_log(
        db, user_id=user_id, action_type=action_type, target_type=target_type,
        date_from=date_from, date_to=date_to,
    )
    return [
        AuditLogEntryResponse(
            id=entry.id,
            user_id=entry.user_id,
            actor_email=actor_email,
            actor_name=actor_name,
            action_type=entry.action_type,
            target_type=entry.target_type,
            target_id=entry.target_id,
            before_value=entry.before_value,
            after_value=entry.after_value,
            timestamp=entry.timestamp,
        )
        for entry, actor_email, actor_name in rows
    ]
