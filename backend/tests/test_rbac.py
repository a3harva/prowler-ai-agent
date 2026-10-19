"""Direct unit tests for the two shared primitives in services/rbac.py.

These tests prove the primitive authorization behavior directly. Admin-only
grant-management endpoints use the global `require_admin` dependency and do
not exercise `require_department_role`.
"""

import pytest

from app.api.deps import CurrentUser
from app.models.department import Department
from app.models.user import User
from app.models.user_department_role import Role, UserDepartmentRole
from app.services.rbac import (
    ALL_DEPARTMENTS,
    DepartmentAccessDeniedError,
    require_department_role,
    visible_department_ids,
)


def _make_user(db_session, email: str) -> User:
    user = User(email=email, name=email)
    db_session.add(user)
    db_session.flush()
    return user


def _make_department(db_session, freshservice_id: str, name: str) -> Department:
    dept = Department(freshservice_id=freshservice_id, name=name, domains=[], deleted=False)
    db_session.add(dept)
    db_session.flush()
    return dept


def _grant(db_session, user: User, dept: Department, role: Role) -> None:
    db_session.add(UserDepartmentRole(user_id=user.id, department_id=dept.id, role=role))
    db_session.flush()


# ── visible_department_ids ──────────────────────────────────────────────────


def test_global_admin_sees_all_departments_sentinel(db_session):
    admin_user = _make_user(db_session, "admin@example.test")
    current = CurrentUser(user=admin_user, is_bootstrap_admin=True)

    assert visible_department_ids(db_session, current) == ALL_DEPARTMENTS


def test_ungranted_user_sees_no_departments(db_session):
    user = _make_user(db_session, "nobody@example.test")
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    assert visible_department_ids(db_session, current) == set()


def test_user_sees_only_granted_departments(db_session):
    user = _make_user(db_session, "engineer@example.test")
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    _make_department(db_session, "3", "Dept C — no grant")
    _grant(db_session, user, dept_a, Role.viewer)
    _grant(db_session, user, dept_b, Role.editor)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    assert visible_department_ids(db_session, current) == {dept_a.id, dept_b.id}


def test_user_can_hold_different_roles_on_different_departments(db_session):
    user = _make_user(db_session, "multi@example.test")
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    _grant(db_session, user, dept_a, Role.viewer)
    _grant(db_session, user, dept_b, Role.admin)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    require_department_role(db_session, current, department_id=dept_b.id, minimum=Role.admin)
    with pytest.raises(DepartmentAccessDeniedError):
        require_department_role(db_session, current, department_id=dept_a.id, minimum=Role.admin)


# ── require_department_role ─────────────────────────────────────────────────


def test_global_admin_bypasses_grant_requirement(db_session):
    admin_user = _make_user(db_session, "admin2@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    current = CurrentUser(user=admin_user, is_bootstrap_admin=True)

    # No grant exists at all, and it still passes at the highest bar.
    require_department_role(db_session, current, department_id=dept.id, minimum=Role.admin)


def test_viewer_refused_at_editor_minimum(db_session):
    user = _make_user(db_session, "viewer@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    _grant(db_session, user, dept, Role.viewer)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    with pytest.raises(DepartmentAccessDeniedError):
        require_department_role(db_session, current, department_id=dept.id, minimum=Role.editor)


def test_editor_passes_at_editor_minimum(db_session):
    user = _make_user(db_session, "editor@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    _grant(db_session, user, dept, Role.editor)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    require_department_role(db_session, current, department_id=dept.id, minimum=Role.editor)


def test_editor_refused_at_admin_minimum(db_session):
    user = _make_user(db_session, "editor2@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    _grant(db_session, user, dept, Role.editor)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    with pytest.raises(DepartmentAccessDeniedError):
        require_department_role(db_session, current, department_id=dept.id, minimum=Role.admin)


def test_department_admin_passes_at_every_minimum(db_session):
    user = _make_user(db_session, "deptadmin@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    _grant(db_session, user, dept, Role.admin)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    for minimum in (Role.viewer, Role.editor, Role.admin):
        require_department_role(db_session, current, department_id=dept.id, minimum=minimum)


def test_no_grant_refused_even_at_viewer_minimum(db_session):
    user = _make_user(db_session, "nogrant@example.test")
    dept = _make_department(db_session, "1", "Dept A")
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    with pytest.raises(DepartmentAccessDeniedError):
        require_department_role(db_session, current, department_id=dept.id, minimum=Role.viewer)


def test_grant_on_a_different_department_does_not_leak_access(db_session):
    user = _make_user(db_session, "scoped@example.test")
    dept_a = _make_department(db_session, "1", "Dept A")
    dept_b = _make_department(db_session, "2", "Dept B")
    _grant(db_session, user, dept_a, Role.admin)
    current = CurrentUser(user=user, is_bootstrap_admin=False)

    with pytest.raises(DepartmentAccessDeniedError):
        require_department_role(db_session, current, department_id=dept_b.id, minimum=Role.viewer)
