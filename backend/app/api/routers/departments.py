from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.config import Settings, get_settings
from app.db import get_db
from app.integrations.freshservice import FreshserviceNotFoundError, FreshserviceUnavailableError
from app.schemas.department import DepartmentCreateRequest, DepartmentResponse
from app.services.departments import (
    add_department,
    delete_department,
    list_departments,
    refresh_department,
)
from app.services.rbac import visible_department_ids

router = APIRouter(prefix="/api/departments", tags=["departments"])


@router.get("", response_model=list[DepartmentResponse])
def list_departments_endpoint(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Readable by any signed-in user, scoped through `visible_department_ids`
    exactly as the organizations and projects listings are. This is broader
    than an Admin-only listing because
    without it non-admins can only ever see raw department ids, and no
    department-scoped screen (scan submission, findings, compliance) can name
    what it is showing. Every *mutation* below stays `require_admin`.
    """
    return list_departments(
        db,
        include_deleted=include_deleted,
        visible_department_ids=visible_department_ids(db, current),
    )


@router.post("", response_model=DepartmentResponse, status_code=status.HTTP_201_CREATED)
def create_department(
    body: DepartmentCreateRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: CurrentUser = Depends(require_admin),
):
    return add_department(
        db,
        freshservice_id=body.freshservice_id,
        actor_user_id=current.user.id,
        settings=settings,
    )


@router.post("/{department_id}/delete", response_model=DepartmentResponse)
def delete_department_endpoint(
    department_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    return delete_department(db, department_id=department_id, actor_user_id=current.user.id)


@router.post("/{department_id}/refresh", response_model=DepartmentResponse)
def refresh_department_endpoint(
    department_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: CurrentUser = Depends(require_admin),
):
    return refresh_department(
        db, department_id=department_id, actor_user_id=current.user.id, settings=settings
    )
