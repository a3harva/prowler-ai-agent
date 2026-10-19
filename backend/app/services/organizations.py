"""Single write path for `gcp_organizations`. Organizations carry their own
`deleted` flag in addition to inheriting
hidden-when-parent-deleted visibility from their department — both are
independent reasons a row can be hidden from `list_organizations`, and
`include_deleted` / `include_deleted_departments` are the escape hatches
back to each.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.services import audit
from app.services.departments import DepartmentNotFoundError
from app.services.rbac import ALL_DEPARTMENTS
from app.services.errors import ConflictError, NotFoundError


class OrganizationAlreadyExistsError(ConflictError):
    def __init__(self, org_id: str):
        super().__init__(f"an organization for org_id '{org_id}' already exists")
        self.org_id = org_id


class OrganizationNotFoundError(NotFoundError):
    def __init__(self, organization_id: int):
        super().__init__(f"no organization with id {organization_id}")


def department_id_for_organization(db: Session, organization_id: int) -> int | None:
    """Looked up before a project mutation so the caller can run the
    department-role check ahead of committing anything. Returns None for an
    organization that doesn't exist — the caller should treat that as "not
    found", not as a permission question (mirrors
    scans.py::department_id_for_project)."""
    org = db.get(GcpOrganization, organization_id)
    return org.department_id if org is not None else None


def list_organizations(
    db: Session,
    *,
    visible_department_ids: set[int] | str,
    include_deleted: bool = False,
    include_deleted_departments: bool = False,
) -> list[GcpOrganization]:
    stmt = select(GcpOrganization).join(Department, Department.id == GcpOrganization.department_id)
    if not include_deleted:
        stmt = stmt.where(GcpOrganization.deleted.is_(False))
    if not include_deleted_departments:
        stmt = stmt.where(Department.deleted.is_(False))
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(GcpOrganization.department_id.in_(visible_department_ids))
    stmt = stmt.order_by(GcpOrganization.name)
    return list(db.execute(stmt).scalars())


def register_organization(
    db: Session, *, org_id: str, name: str, department_id: int, actor_user_id: int
) -> GcpOrganization:
    department = db.get(Department, department_id)
    if department is None:
        raise DepartmentNotFoundError(department_id)

    # Only an active row blocks re-registration — a deleted organization's id
    # is free to reuse. The partial unique index backs this same rule at the
    # DB level (see the IntegrityError catch below).
    existing = db.execute(
        select(GcpOrganization).where(
            GcpOrganization.org_id == org_id, GcpOrganization.deleted.is_(False)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise OrganizationAlreadyExistsError(org_id)

    org = GcpOrganization(org_id=org_id, name=name, department_id=department_id, deleted=False)
    db.add(org)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise OrganizationAlreadyExistsError(org_id) from exc

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="gcp_organization.create",
        target_type="gcp_organization",
        target_id=str(org.id),
        before_value=None,
        after_value={"org_id": org.org_id, "name": org.name, "department_id": org.department_id},
    )
    db.commit()
    db.refresh(org)
    return org


def update_organization(
    db: Session, *, organization_id: int, name: str, department_id: int, actor_user_id: int
) -> GcpOrganization:
    """`org_id` is not a parameter here at all — not validated-and-rejected,
    structurally absent — so this can never be the path that changes it."""
    org = db.get(GcpOrganization, organization_id)
    if org is None:
        raise OrganizationNotFoundError(organization_id)

    department = db.get(Department, department_id)
    if department is None:
        raise DepartmentNotFoundError(department_id)

    before_value = {"name": org.name, "department_id": org.department_id}
    org.name = name
    org.department_id = department_id
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="gcp_organization.update",
        target_type="gcp_organization",
        target_id=str(org.id),
        before_value=before_value,
        after_value={"name": org.name, "department_id": org.department_id},
    )
    db.commit()
    db.refresh(org)
    return org


def delete_organization(db: Session, *, organization_id: int, actor_user_id: int) -> GcpOrganization:
    """Soft delete — the row and everything hanging off it (projects, scans,
    audit history) stays in the DB, just hidden from default listings.
    Deleting frees `org_id` up for reuse; there is no separate restore
    action, re-registering the same id is the recovery path."""
    org = db.get(GcpOrganization, organization_id)
    if org is None:
        raise OrganizationNotFoundError(organization_id)

    before_value = {"deleted": org.deleted}
    org.deleted = True
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="gcp_organization.delete",
        target_type="gcp_organization",
        target_id=str(org.id),
        before_value=before_value,
        after_value={"deleted": org.deleted},
    )
    db.commit()
    db.refresh(org)
    return org
