"""Audit trail foundation. `record(...)` is called explicitly at each mutation
site, inside the same transaction as the change it describes — never as a
decorator, since a decorator cannot capture a meaningful `before_value`.

Callers must NOT commit inside this function: the caller's own commit is what
makes the audit entry and the mutation atomic. A caller that rolls back after
calling `record` loses the entry along with the mutation, by design.
"""

import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User

# Safety cap, not pagination — this is a viewing screen, not an export.
# A single query result this size is still a small payload; if the trail
# ever legitimately grows past it, that's the point to add real pagination,
# not to raise this number blindly.
_MAX_RESULTS = 1000


def record(
    db: Session,
    *,
    user_id: int,
    action_type: str,
    target_type: str,
    target_id: str,
    before_value: dict | None,
    after_value: dict | None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action_type=action_type,
        target_type=target_type,
        target_id=str(target_id),
        before_value=before_value,
        after_value=after_value,
    )
    db.add(entry)
    db.flush()
    return entry


def list_audit_log(
    db: Session,
    *,
    user_id: int | None = None,
    action_type: str | None = None,
    target_type: str | None = None,
    date_from: datetime.datetime | None = None,
    date_to: datetime.datetime | None = None,
) -> list[tuple[AuditLog, str, str]]:
    """Every filter is optional and they combine with AND — making them
    work in combination is just SQLAlchemy's normal `.where()`
    chaining, nothing bespoke needed. Returns `(entry, actor_email,
    actor_name)` tuples rather than bare `AuditLog` rows so the caller never
    has to N+1 a second lookup per row just to show who did it — the whole
    point of an audit trail is being able to say who."""
    stmt = (
        select(AuditLog, User.email, User.name)
        .join(User, User.id == AuditLog.user_id)
        # id as the tie-break, not just timestamp: two entries in the same
        # transaction (or just fast enough) can share a `now()` value down
        # to the microsecond, and insertion order is still the true
        # "most recent first" the moment timestamps alone can't decide it.
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .limit(_MAX_RESULTS)
    )
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if action_type is not None:
        stmt = stmt.where(AuditLog.action_type == action_type)
    if target_type is not None:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if date_from is not None:
        stmt = stmt.where(AuditLog.timestamp >= date_from)
    if date_to is not None:
        stmt = stmt.where(AuditLog.timestamp <= date_to)
    return list(db.execute(stmt).all())
