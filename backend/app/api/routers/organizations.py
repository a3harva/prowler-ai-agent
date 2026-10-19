from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.db import get_db
from app.schemas.organization import (
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
)
from app.services.organizations import (
    delete_organization,
    list_organizations,
    register_organization,
    update_organization,
)
from app.services.rbac import visible_department_ids

router = APIRouter(prefix="/api/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationResponse])
def list_organizations_endpoint(
    include_deleted: bool = False,
    include_deleted_departments: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    return list_organizations(
        db,
        visible_department_ids=visible,
        include_deleted=include_deleted,
        include_deleted_departments=include_deleted_departments,
    )


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def register_organization_endpoint(
    body: OrganizationCreateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    return register_organization(
        db,
        org_id=body.org_id,
        name=body.name,
        department_id=body.department_id,
        actor_user_id=current.user.id,
    )


@router.put("/{organization_id}", response_model=OrganizationResponse)
def update_organization_endpoint(
    organization_id: int,
    body: OrganizationUpdateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    return update_organization(
        db,
        organization_id=organization_id,
        name=body.name,
        department_id=body.department_id,
        actor_user_id=current.user.id,
    )


@router.post("/{organization_id}/delete", response_model=OrganizationResponse)
def delete_organization_endpoint(
    organization_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    return delete_organization(db, organization_id=organization_id, actor_user_id=current.user.id)
