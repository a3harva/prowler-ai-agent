"""Single write path for `projects`. Registration is record-keeping only —
the IAM grant that lets a scan actually impersonate `target_sa_email` happens
out-of-band, outside this application. Nothing here verifies it; that
statement belongs at the point of registration in the interface, not as a
backend check this service can't perform anyway.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.department import Department
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.services import audit
# The canonical class, not a second one with the same name — the two that
# used to exist even took differently-named arguments.
from app.services.organizations import OrganizationNotFoundError
from app.services.rbac import ALL_DEPARTMENTS
from app.services.errors import ConflictError, NotFoundError


class ProjectAlreadyExistsError(ConflictError):
    def __init__(self, project_id: str):
        super().__init__(f"a project for project_id '{project_id}' already exists")
        self.project_id = project_id


class ProjectNotFoundError(NotFoundError):
    def __init__(self, project_id: int):
        super().__init__(f"no project with id {project_id}")


def list_projects(
    db: Session,
    *,
    visible_department_ids: set[int] | str,
    include_deleted: bool = False,
    include_deleted_departments: bool = False,
) -> list[Project]:
    stmt = (
        select(Project)
        .join(GcpOrganization, GcpOrganization.id == Project.gcp_organization_id)
        .join(Department, Department.id == GcpOrganization.department_id)
    )
    if not include_deleted:
        stmt = stmt.where(Project.deleted.is_(False))
    if not include_deleted_departments:
        stmt = stmt.where(Department.deleted.is_(False))
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(GcpOrganization.department_id.in_(visible_department_ids))
    stmt = stmt.order_by(Project.project_id)
    return list(db.execute(stmt).scalars())


def register_project(
    db: Session, *, project_id: str, gcp_organization_id: int, target_sa_email: str, actor_user_id: int
) -> Project:
    org = db.get(GcpOrganization, gcp_organization_id)
    if org is None:
        raise OrganizationNotFoundError(gcp_organization_id)

    # Only an active row blocks re-registration — a deleted project's id is
    # free to reuse. The partial unique index backs this same rule at the
    # DB level (see the IntegrityError catch below).
    existing = db.execute(
        select(Project).where(Project.project_id == project_id, Project.deleted.is_(False))
    ).scalar_one_or_none()
    if existing is not None:
        raise ProjectAlreadyExistsError(project_id)

    project = Project(
        project_id=project_id,
        gcp_organization_id=gcp_organization_id,
        target_sa_email=target_sa_email,
        deleted=False,
    )
    db.add(project)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ProjectAlreadyExistsError(project_id) from exc

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="project.create",
        target_type="project",
        target_id=str(project.id),
        before_value=None,
        after_value={
            "project_id": project.project_id,
            "gcp_organization_id": project.gcp_organization_id,
            "target_sa_email": project.target_sa_email,
            "deleted": project.deleted,
        },
    )
    db.commit()
    db.refresh(project)
    return project


def update_project(
    db: Session, *, project_id: int, gcp_organization_id: int, target_sa_email: str, actor_user_id: int
) -> Project:
    """The project's own `project_id` (the GCP identifier) is not a
    parameter here at all — not validated-and-rejected, structurally
    absent — so this can never be the path that changes it."""
    project = db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    org = db.get(GcpOrganization, gcp_organization_id)
    if org is None:
        raise OrganizationNotFoundError(gcp_organization_id)

    before_value = {
        "gcp_organization_id": project.gcp_organization_id,
        "target_sa_email": project.target_sa_email,
    }
    project.gcp_organization_id = gcp_organization_id
    project.target_sa_email = target_sa_email
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="project.update",
        target_type="project",
        target_id=str(project.id),
        before_value=before_value,
        after_value={
            "gcp_organization_id": project.gcp_organization_id,
            "target_sa_email": project.target_sa_email,
        },
    )
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, *, project_id: int, actor_user_id: int) -> Project:
    """Soft delete — the row and everything hanging off it (scans, findings,
    audit history) stays in the DB, just hidden from default listings.
    Deleting frees `project_id` up for reuse; there is no separate restore
    action, re-registering the same id is the recovery path."""
    project = db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    before_value = {"deleted": project.deleted}
    project.deleted = True
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="project.delete",
        target_type="project",
        target_id=str(project.id),
        before_value=before_value,
        after_value={"deleted": project.deleted},
    )
    db.commit()
    db.refresh(project)
    return project
