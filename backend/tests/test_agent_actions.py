"""The propose → confirm → execute gate.

The property under test is not "does a mute happen" but "can a mute happen
without a human having confirmed exactly that mute" — which is what makes the
banner load-bearing rather than decorative.
"""

import datetime

import pytest

from app.models.agent import PendingAction, PendingActionStatus
from app.models.audit_log import AuditLog
from app.models.finding import MuteReason
from app.models.user_department_role import Role
from app.services import agent as agent_service
from app.services import agent_tools
from app.services.errors import PermissionDeniedError
from tests.test_agent_tools import (
    _Current,
    _ctx,
    _make_finding,
    _make_project,
    _make_scan,
    _make_user,
)


def _seed(db, *, role=Role.editor):
    project, dept = _make_project(db, "a")
    user = _make_user(db, "editor@example.test", dept.id, role=role)
    scan = _make_scan(db, project, user)
    finding = _make_finding(db, project, scan)
    db.commit()
    return project, dept, user, finding


def test_apply_executes_the_stored_arguments(db_session):
    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(
        ctx, finding_id=finding.id, mute_reason="false_positive", note="not reachable"
    )
    db_session.commit()

    assert finding.muted is False  # still nothing has happened

    agent_service.apply_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )
    db_session.refresh(finding)
    assert finding.muted is True
    assert finding.mute_reason == MuteReason.false_positive
    assert finding.note == "not reachable"


def test_an_action_cannot_be_applied_twice(db_session):
    """Single-use. A replayed confirm request must not re-run the write —
    which for `mute_check` would otherwise be a second bulk apply over rows a
    human may have unmuted in between."""
    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    agent_service.apply_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )
    with pytest.raises(agent_service.PendingActionNotActionableError):
        agent_service.apply_pending_action(
            db_session, action_id=proposal["action_id"], current=_Current(user)
        )


def test_an_expired_action_is_refused(db_session):
    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    action = db_session.get(PendingAction, proposal["action_id"])
    action.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    db_session.commit()

    with pytest.raises(agent_service.PendingActionNotActionableError):
        agent_service.apply_pending_action(
            db_session, action_id=proposal["action_id"], current=_Current(user)
        )
    db_session.refresh(action)
    assert action.status == PendingActionStatus.expired
    db_session.refresh(finding)
    assert finding.muted is False


def test_another_user_cannot_apply_your_pending_action(db_session):
    """A confirmation is personal. Someone else holding editor on the same
    department still may not click your banner — the id is not a capability
    anyone may spend."""
    project, dept, user, finding = _seed(db_session)
    other = _make_user(db_session, "other-editor@example.test", dept.id, role=Role.editor)
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    with pytest.raises(agent_service.PendingActionNotFoundError):
        agent_service.apply_pending_action(
            db_session, action_id=proposal["action_id"], current=_Current(other)
        )


def test_a_grant_revoked_after_proposal_loses(db_session):
    """The gate re-runs at apply time rather than trusting the check made when
    the action was proposed — the whole point of re-checking rather than
    caching `can_write` on the session."""
    from app.models.user_department_role import UserDepartmentRole

    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    grant = (
        db_session.query(UserDepartmentRole)
        .filter_by(user_id=user.id, department_id=dept.id)
        .one()
    )
    grant.role = Role.viewer
    db_session.commit()

    with pytest.raises(PermissionDeniedError):
        agent_service.apply_pending_action(
            db_session, action_id=proposal["action_id"], current=_Current(user)
        )
    db_session.refresh(finding)
    assert finding.muted is False


def test_discard_leaves_the_finding_alone(db_session):
    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    agent_service.discard_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )
    db_session.refresh(finding)
    assert finding.muted is False
    with pytest.raises(agent_service.PendingActionNotActionableError):
        agent_service.apply_pending_action(
            db_session, action_id=proposal["action_id"], current=_Current(user)
        )


def test_applying_writes_both_audit_trails(db_session):
    """`update_finding` already records a per-finding entry; the agent adds
    one naming the session, so the log can answer "which conversation produced
    this mute" — which the finding-level entries alone cannot."""
    project, dept, user, finding = _seed(db_session)
    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")
    db_session.commit()

    agent_service.apply_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )
    kinds = {row.action_type for row in db_session.query(AuditLog).all()}
    assert "finding.update" in kinds
    assert "agent.action.apply" in kinds


def test_set_finding_note_does_not_change_mute_state(db_session):
    """A note-only edit carries mute state through unchanged rather than
    reasserting it, so an annotation can never silently unmute."""
    project, dept, user, finding = _seed(db_session)
    finding.muted = True
    finding.mute_reason = MuteReason.risk_accepted
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.set_finding_note(ctx, finding_id=finding.id, note="revisit in Q3")
    db_session.commit()
    agent_service.apply_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )

    db_session.refresh(finding)
    assert finding.note == "revisit in Q3"
    assert finding.muted is True
    assert finding.mute_reason == MuteReason.risk_accepted


def test_mute_check_applies_to_every_unmuted_row(db_session):
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    for i in range(3):
        _make_finding(db_session, project, scan, check_id="bulk", resource=f"r{i}")
    already = _make_finding(
        db_session, project, scan, check_id="bulk", resource="r-muted", muted=True
    )
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    proposal = agent_tools.mute_check(ctx, check_id="bulk", mute_reason="compensating_control")
    db_session.commit()
    # The banner promises exactly the rows that will change — already-muted
    # ones are excluded from the count, matching mute_by_check's own rule.
    assert proposal["summary"]["affected_count"] == 3

    result = agent_service.apply_pending_action(
        db_session, action_id=proposal["action_id"], current=_Current(user)
    )
    assert result["muted_count"] == 3

    # And a bulk apply never overwrites a judgement a human already made.
    db_session.refresh(already)
    assert already.mute_reason == MuteReason.risk_accepted


def test_session_creation_requires_a_grant(db_session):
    project, dept = _make_project(db_session, "a")
    outsider_project, outsider_dept = _make_project(db_session, "b")
    user = _make_user(db_session, "editor@example.test", dept.id)
    db_session.commit()

    with pytest.raises(PermissionDeniedError):
        agent_service.create_session(
            db_session, project_pk=outsider_project.id, current=_Current(user)
        )
    session = agent_service.create_session(
        db_session, project_pk=project.id, current=_Current(user)
    )
    assert session.project_id == project.id


def test_a_session_is_private_to_its_owner(db_session):
    project, dept, user, _finding = _seed(db_session)
    other = _make_user(db_session, "other@example.test", dept.id)
    db_session.commit()
    session = agent_service.create_session(db_session, project_pk=project.id, current=_Current(user))

    with pytest.raises(agent_service.AgentSessionNotFoundError):
        agent_service.get_session(db_session, session_id=session.id, current=_Current(other))
