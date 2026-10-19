"""Single write path for `departments`. Both mutations here call
`services/audit.py::record(...)` inside the same transaction as the row
change and commit together — a rollback (e.g. the IntegrityError path in
`add_department`) takes the audit entry down with it.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.integrations.freshservice import FreshserviceError, fetch_department
from app.models.department import Department
from app.services import audit
from app.services.rbac import ALL_DEPARTMENTS
from app.services.errors import ConflictError, NotFoundError


class DepartmentNotFoundError(NotFoundError):
    """Defined here, in the module that owns departments, and imported by
    `services/organizations.py` rather than redeclared there — a second class
    with this name would be a different type, so an `except` on the wrong
    import would quietly never match."""

    def __init__(self, department_id: int):
        super().__init__(f"no department with id {department_id}")
        self.department_id = department_id


class DepartmentAlreadyExistsError(ConflictError):
    def __init__(self, freshservice_id: str):
        super().__init__(f"a department for Freshservice id '{freshservice_id}' already exists")
        self.freshservice_id = freshservice_id


def list_departments(
    db: Session,
    *,
    include_deleted: bool = False,
    visible_department_ids: set[int] | str = ALL_DEPARTMENTS,
) -> list[Department]:
    """Reading departments is scoped the same way organizations and projects
    are — a non-admin sees only the departments they hold a grant on. The
    default is ALL_DEPARTMENTS so existing admin-only callers keep their
    current behaviour without passing the argument.
    """
    stmt = select(Department).order_by(Department.name)
    if not include_deleted:
        stmt = stmt.where(Department.deleted.is_(False))
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(Department.id.in_(visible_department_ids))
    return list(db.execute(stmt).scalars())


def add_department(
    db: Session, *, freshservice_id: str, actor_user_id: int, settings: Settings
) -> Department:
    freshservice_id = freshservice_id.strip()

    # Only an active row blocks re-registration — a deleted department's id
    # is free to reuse. The partial unique index backs this same rule at the
    # DB level (see the IntegrityError catch below).
    existing = db.execute(
        select(Department).where(
            Department.freshservice_id == freshservice_id, Department.deleted.is_(False)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise DepartmentAlreadyExistsError(freshservice_id)

    # Raises FreshserviceNotFoundError / FreshserviceUnavailableError — both
    # propagate uncaught, before anything is written.
    fetched = fetch_department(
        freshservice_id,
        domain=settings["FRESHSERVICE_DOMAIN"],
        api_key=settings["FRESHSERVICE_API_KEY"],
    )

    department = Department(
        freshservice_id=fetched.freshservice_id,
        name=fetched.name,
        domains=fetched.domains,
        deleted=False,
    )
    db.add(department)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise DepartmentAlreadyExistsError(freshservice_id) from exc

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="department.create",
        target_type="department",
        target_id=str(department.id),
        before_value=None,
        after_value={
            "freshservice_id": department.freshservice_id,
            "name": department.name,
            "domains": department.domains,
            "deleted": department.deleted,
        },
    )
    db.commit()
    db.refresh(department)
    return department


def refresh_department(
    db: Session, *, department_id: int, actor_user_id: int, settings: Settings
) -> Department:
    """Re-fetches name/domains from Freshservice and overwrites the stored
    copy — the fix for domains added in Freshservice *after* onboarding,
    since the department is otherwise never re-read. `freshservice_id` is
    the fetch key and never changes; `deleted` is a local decision and is
    untouched here."""
    department = db.get(Department, department_id)
    if department is None:
        raise DepartmentNotFoundError(department_id)

    # Raises FreshserviceNotFoundError / FreshserviceUnavailableError — both
    # propagate uncaught, before anything is written.
    fetched = fetch_department(
        department.freshservice_id,
        domain=settings["FRESHSERVICE_DOMAIN"],
        api_key=settings["FRESHSERVICE_API_KEY"],
    )

    before_value = {"name": department.name, "domains": department.domains}
    department.name = fetched.name
    department.domains = fetched.domains
    db.flush()

    after_value = {"name": department.name, "domains": department.domains}
    if before_value != after_value:
        audit.record(
            db,
            user_id=actor_user_id,
            action_type="department.refresh",
            target_type="department",
            target_id=str(department.id),
            before_value=before_value,
            after_value=after_value,
        )
    db.commit()
    db.refresh(department)
    return department


def delete_department(db: Session, *, department_id: int, actor_user_id: int) -> Department:
    """Soft delete — the row and everything hanging off it (organizations,
    projects, scans, audit history) stays in the DB, just hidden from
    default listings. Deleting frees `freshservice_id` up for reuse; there
    is no separate restore action, re-adding the same id is the recovery
    path."""
    department = db.get(Department, department_id)
    if department is None:
        raise DepartmentNotFoundError(department_id)

    before_value = {"deleted": department.deleted}
    department.deleted = True
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="department.delete",
        target_type="department",
        target_id=str(department.id),
        before_value=before_value,
        after_value={"deleted": department.deleted},
    )
    db.commit()
    db.refresh(department)
    return department
