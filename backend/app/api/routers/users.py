from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, require_admin
from app.db import get_db
from app.models.user import User
from app.schemas.user import GrantRequest, RoleChangeRequest, SetPasswordRequest, UserWithGrantsResponse
from app.services.users import (
    change_role,
    grant_role,
    list_grants_for_user,
    list_users_with_grants,
    remove_role,
    set_user_password,
)

router = APIRouter(prefix="/api/users", tags=["users"])


def _with_grants(db: Session, user: User) -> UserWithGrantsResponse:
    return UserWithGrantsResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        has_password=user.password_hash is not None,
        grants=list_grants_for_user(db, user.id),
    )


@router.get("", response_model=list[UserWithGrantsResponse])
def list_users_endpoint(db: Session = Depends(get_db), current: CurrentUser = Depends(require_admin)):
    return [_with_grants(db, user) for user in list_users_with_grants(db)]


@router.post("", response_model=UserWithGrantsResponse, status_code=status.HTTP_201_CREATED)
def grant_role_endpoint(
    body: GrantRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    grant = grant_role(
        db,
        email=body.email,
        department_id=body.department_id,
        role=body.role,
        actor_user_id=current.user.id,
    )

    user = db.get(User, grant.user_id)
    return _with_grants(db, user)


@router.post("/password", response_model=UserWithGrantsResponse)
def set_password_endpoint(
    body: SetPasswordRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    user = set_user_password(
        db,
        email=body.email,
        new_password=body.password,
        actor_user_id=current.user.id,
    )
    return _with_grants(db, user)


@router.put("/{user_id}/roles/{department_id}", response_model=UserWithGrantsResponse)
def change_role_endpoint(
    user_id: int,
    department_id: int,
    body: RoleChangeRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    change_role(
        db,
        user_id=user_id,
        department_id=department_id,
        role=body.role,
        actor_user_id=current.user.id,
    )

    user = db.get(User, user_id)
    return _with_grants(db, user)


@router.delete("/{user_id}/roles/{department_id}", response_model=UserWithGrantsResponse)
def remove_role_endpoint(
    user_id: int,
    department_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    remove_role(db, user_id=user_id, department_id=department_id, actor_user_id=current.user.id)

    user = db.get(User, user_id)
    return _with_grants(db, user)
