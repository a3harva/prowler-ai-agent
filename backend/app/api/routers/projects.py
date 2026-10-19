from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user
from app.db import get_db
from app.models.user_department_role import Role
from app.schemas.project import ProjectCreateRequest, ProjectResponse, ProjectUpdateRequest
from app.services.organizations import department_id_for_organization
from app.services.projects import (
    delete_project,
    list_projects,
    register_project,
    update_project,
)
from app.services.rbac import require_department_role, visible_department_ids
from app.services.scans import department_id_for_project

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectResponse])
def list_projects_endpoint(
    include_deleted: bool = False,
    include_deleted_departments: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    return list_projects(
        db,
        visible_department_ids=visible,
        include_deleted=include_deleted,
        include_deleted_departments=include_deleted_departments,
    )


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def register_project_endpoint(
    body: ProjectCreateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    # A department Admin has full control of their own department (see the
    # role's own description on the Users page), which includes registering
    # projects under an organization that belongs to it — not just the
    # global bootstrap admin. A missing organization fails closed before any
    # mutation or task can be created.
    department_id = department_id_for_organization(db, body.gcp_organization_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.admin)

    return register_project(
        db,
        project_id=body.project_id,
        gcp_organization_id=body.gcp_organization_id,
        target_sa_email=body.target_sa_email,
        actor_user_id=current.user.id,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project_endpoint(
    project_id: int,
    body: ProjectUpdateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    current_department_id = department_id_for_project(db, project_id)
    require_department_role(db, current, department_id=current_department_id, minimum=Role.admin)

    # Moving a project to a different organization also requires admin on
    # the destination department — otherwise a department admin could move
    # a project they administer into an org they do not.
    target_department_id = department_id_for_organization(db, body.gcp_organization_id)
    if target_department_id != current_department_id:
        require_department_role(db, current, department_id=target_department_id, minimum=Role.admin)

    return update_project(
        db,
        project_id=project_id,
        gcp_organization_id=body.gcp_organization_id,
        target_sa_email=body.target_sa_email,
        actor_user_id=current.user.id,
    )


@router.post("/{project_id}/delete", response_model=ProjectResponse)
def delete_project_endpoint(
    project_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    department_id = department_id_for_project(db, project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.admin)

    return delete_project(db, project_id=project_id, actor_user_id=current.user.id)
