"""Single write path for `users` and `user_department_roles`. First sign-in
inserts; every later sign-in updates the same row rather than duplicating —
the upsert is what makes this true, not caller discipline.

Grants are keyed on (user_id, department_id): `grant_role` creates, requiring
no existing row; `change_role` and `remove_role` require one. Splitting them
this way is what lets grant/change/remove be three distinct, individually
audited actions instead of one upsert that blurs "this is new access" into
"this replaced existing access".
"""

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.auth.passwords import hash_password
from app.models.department import Department
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services import audit
from app.services.errors import ConflictError, NotFoundError


def upsert_user_from_login(db: Session, *, email: str, name: str) -> User:
    stmt = (
        insert(User)
        .values(email=email, name=name, last_login_at=func.now())
        .on_conflict_do_update(
            index_elements=[User.email],
            # Deliberately excludes password_hash: a Google login must never
            # clobber a password set via set_user_password, and vice versa.
            set_={"name": name, "last_login_at": func.now()},
        )
        .returning(User)
    )
    user = db.execute(stmt).scalar_one()
    db.commit()
    return user


def get_or_create_user_by_email(db: Session, *, email: str) -> User:
    """Used only by the Admin grant flow, where a user may not have signed in
    yet. `name` is a placeholder (the email itself) until the real sign-in —
    which happens on any subsequent login, since upsert_user_from_login
    always overwrites `name` — so no separate "pending user" state exists."""
    email = email.strip().lower()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None:
        return user
    user = User(email=email, name=email)
    db.add(user)
    db.flush()
    return user


def set_user_password(db: Session, *, email: str, new_password: str, actor_user_id: int) -> User:
    """Admin-only. Auto-provisions the user by email (same pattern as
    grant_role/get_or_create_user_by_email) so an admin can create a
    password-only test identity without needing a department grant first.
    """
    user = get_or_create_user_by_email(db, email=email)

    before_had_password = user.password_hash is not None
    user.password_hash = hash_password(new_password)
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="user.set_password",
        target_type="user",
        target_id=str(user.id),
        before_value={"had_password": before_had_password},
        after_value={"had_password": True},
    )
    db.commit()
    db.refresh(user)
    return user


class GrantAlreadyExistsError(ConflictError):
    def __init__(self, user_id: int, department_id: int):
        super().__init__(f"user {user_id} already has a role on department {department_id}")


class GrantNotFoundError(NotFoundError):
    def __init__(self, user_id: int, department_id: int):
        super().__init__(f"user {user_id} has no role on department {department_id}")


def list_users_with_grants(db: Session) -> list[User]:
    return list(db.execute(select(User).order_by(User.email)).scalars())


def list_grants_for_user(db: Session, user_id: int) -> list[UserDepartmentRole]:
    return list(
        db.execute(
            select(UserDepartmentRole)
            .where(UserDepartmentRole.user_id == user_id)
            .join(Department, Department.id == UserDepartmentRole.department_id)
            .order_by(Department.name)
        ).scalars()
    )


def grant_role(
    db: Session, *, email: str, department_id: int, role: Role, actor_user_id: int
) -> UserDepartmentRole:
    user = get_or_create_user_by_email(db, email=email)

    existing = db.execute(
        select(UserDepartmentRole).where(
            UserDepartmentRole.user_id == user.id,
            UserDepartmentRole.department_id == department_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise GrantAlreadyExistsError(user.id, department_id)

    grant = UserDepartmentRole(user_id=user.id, department_id=department_id, role=role)
    db.add(grant)
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="user_department_role.grant",
        target_type="user_department_role",
        target_id=f"{user.id}:{department_id}",
        before_value=None,
        after_value={"user_id": user.id, "email": user.email, "department_id": department_id, "role": role.value},
    )
    db.commit()
    db.refresh(user)
    return grant


def change_role(
    db: Session, *, user_id: int, department_id: int, role: Role, actor_user_id: int
) -> UserDepartmentRole:
    grant = db.execute(
        select(UserDepartmentRole).where(
            UserDepartmentRole.user_id == user_id,
            UserDepartmentRole.department_id == department_id,
        )
    ).scalar_one_or_none()
    if grant is None:
        raise GrantNotFoundError(user_id, department_id)

    before_value = {"role": grant.role.value}
    grant.role = role
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="user_department_role.change",
        target_type="user_department_role",
        target_id=f"{user_id}:{department_id}",
        before_value=before_value,
        after_value={"role": role.value},
    )
    db.commit()
    db.refresh(grant)
    return grant


def remove_role(db: Session, *, user_id: int, department_id: int, actor_user_id: int) -> None:
    grant = db.execute(
        select(UserDepartmentRole).where(
            UserDepartmentRole.user_id == user_id,
            UserDepartmentRole.department_id == department_id,
        )
    ).scalar_one_or_none()
    if grant is None:
        raise GrantNotFoundError(user_id, department_id)

    before_value = {"role": grant.role.value}
    db.delete(grant)
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="user_department_role.remove",
        target_type="user_department_role",
        target_id=f"{user_id}:{department_id}",
        before_value=before_value,
        after_value=None,
    )
    db.commit()
