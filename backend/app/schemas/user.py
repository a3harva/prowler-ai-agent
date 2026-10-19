import datetime

from pydantic import BaseModel, ConfigDict

from app.models.user_department_role import Role


class GrantRequest(BaseModel):
    email: str
    department_id: int
    role: Role


class RoleChangeRequest(BaseModel):
    role: Role


class SetPasswordRequest(BaseModel):
    email: str
    password: str


class DepartmentGrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    department_id: int
    role: Role


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    name: str
    created_at: datetime.datetime
    last_login_at: datetime.datetime | None


class UserWithGrantsResponse(UserResponse):
    has_password: bool
    grants: list[DepartmentGrantResponse]


class CurrentUserResponse(BaseModel):
    """What `/api/auth/me` tells the browser about the signed-in user.

    `grants` is what lets the interface hide controls a Viewer cannot use.
    Without it the frontend knows only `is_bootstrap_admin` and cannot
    distinguish Editor from Viewer per department; unavailable controls should
    be absent, not merely rejected on click.

    `is_bootstrap_admin` is global admin and comes from
    `BOOTSTRAP_ADMIN_EMAILS`, matching `deps.py::require_admin`. A
    department-level `admin` grant appears in `grants` and confers
    department-scoped rights only — it does not satisfy `require_admin`.
    The frontend permission model mirrors that asymmetry rather than
    smoothing it over.
    """

    email: str
    name: str
    is_bootstrap_admin: bool
    grants: list[DepartmentGrantResponse]
