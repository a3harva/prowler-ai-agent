"""The two primitives every scoped endpoint uses, so scope is derived in one
place rather than re-derived per router. `is_bootstrap_admin` (the global
escape hatch) always wins here — it is *additive* over any
per-department grant, never a separate silo: a global Admin sees and can do
everything without needing a row in `user_department_roles` for every
department.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.errors import NotFoundError, PermissionDeniedError

_ROLE_ORDER = {Role.viewer: 0, Role.editor: 1, Role.admin: 2}

# Sentinel returned by visible_department_ids for a global admin — "every
# department", not a literal (and staleness-prone) list of every id.
ALL_DEPARTMENTS = "ALL"


class DepartmentAccessDeniedError(PermissionDeniedError):
    def __init__(self, department_id: int, minimum: Role):
        super().__init__(
            f"role '{minimum.value}' or higher on department {department_id} required"
        )
        self.department_id = department_id
        self.minimum = minimum


class DepartmentResolutionError(NotFoundError):
    """A mutation cannot establish an owning department.

    Failing closed here prevents a missing project, organization, or finding
    from bypassing a router-level authorization check.
    """

    def __init__(self) -> None:
        super().__init__("requested resource was not found")


def visible_department_ids(db: Session, current: CurrentUser) -> set[int] | str:
    """Every department a user is allowed to see. A global admin gets the
    ALL_DEPARTMENTS sentinel; everyone else gets the exact set of department
    ids they hold *any* grant on (viewer included — visibility, not the
    ability to act)."""
    if current.is_bootstrap_admin:
        return ALL_DEPARTMENTS
    rows = db.execute(
        select(UserDepartmentRole.department_id).where(
            UserDepartmentRole.user_id == current.user.id
        )
    ).scalars()
    return set(rows)


def require_department_role(
    db: Session, current: CurrentUser, *, department_id: int | None, minimum: Role
) -> None:
    """Raises DepartmentAccessDeniedError unless the user holds `minimum` or
    higher on `department_id`. A global admin always passes."""
    if department_id is None:
        raise DepartmentResolutionError()
    if current.is_bootstrap_admin:
        return

    grant = db.execute(
        select(UserDepartmentRole).where(
            UserDepartmentRole.user_id == current.user.id,
            UserDepartmentRole.department_id == department_id,
        )
    ).scalar_one_or_none()

    if grant is None or _ROLE_ORDER[grant.role] < _ROLE_ORDER[minimum]:
        raise DepartmentAccessDeniedError(department_id, minimum)


def is_department_visible(department_id: int | None, visible: set[int] | str) -> bool:
    """Whether a single row's owning department falls inside `visible`.

    The by-id counterpart to `visible_department_ids`, which only ever
    produced a set for a list query's WHERE clause. Every by-id read
    (`get_finding`, `get_scan`, `get_report`) went unscoped because there was
    no primitive for "check this one" — the set was the only thing on offer,
    and it does not fit a `db.get()`.

    `department_id` is `None` when the row's department could not be resolved
    at all, which is treated as not visible: a row that cannot prove which
    department owns it must not be readable by someone who is not a global
    admin.
    """
    if visible == ALL_DEPARTMENTS:
        return True
    return department_id is not None and department_id in visible
