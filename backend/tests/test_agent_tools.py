"""The agent's access boundary, tested as a boundary.

The tests that matter most here are not "does the tool return the right
number" but "can this reach outside the session's project" — because the
answer being no is the entire justification for giving a language model a
mute button at all.
"""

import datetime

import pytest

from app.models.compliance_requirement import ComplianceRequirement
from app.models.department import Department
from app.models.finding import Finding, FindingStatus, MuteReason, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.agent import AgentSession
from app.models.user_department_role import Role, UserDepartmentRole
from app.services import agent_schemas, agent_tools
from app.services.agent_tools import ToolContext, ToolError
from app.services.errors import PermissionDeniedError


class _Current:
    """Stands in for `api/deps.CurrentUser` without a request."""

    def __init__(self, user, is_bootstrap_admin=False):
        self.user = user
        self.is_bootstrap_admin = is_bootstrap_admin


def _make_project(db, suffix="a") -> tuple[Project, Department]:
    dept = Department(freshservice_id=f"dept-{suffix}", name=f"Dept {suffix}", domains=[], deleted=False)
    db.add(dept)
    db.flush()
    org = GcpOrganization(org_id=f"org-{suffix}", name=f"Org {suffix}", department_id=dept.id)
    db.add(org)
    db.flush()
    project = Project(
        project_id=f"proj-{suffix}",
        gcp_organization_id=org.id,
        target_sa_email=f"scanner@proj-{suffix}.iam.gserviceaccount.com",
        deleted=False,
    )
    db.add(project)
    db.flush()
    return project, dept


def _make_user(db, email, dept_id=None, role=Role.editor) -> User:
    user = User(email=email, name=email.split("@")[0])
    db.add(user)
    db.flush()
    if dept_id is not None:
        db.add(UserDepartmentRole(user_id=user.id, department_id=dept_id, role=role))
    db.flush()
    return user


def _make_finding(db, project, scan, *, check_id="c1", resource="res-1", severity=Severity.high,
                  status=FindingStatus.FAIL, muted=False, service="compute") -> Finding:
    f = Finding(
        project_id=project.id, check_id=check_id, resource_uid=f"uid-{resource}",
        finding_uid=f"fuid-{resource}", check_title=f"Title for {check_id}",
        severity=severity, status=status, status_extended="detail", region="us-central1",
        service_name=service, resource_type="compute.googleapis.com/Instance",
        resource_name=resource, last_scan_id=scan.id, muted=muted,
        mute_reason=MuteReason.risk_accepted if muted else None,
        description="what", risk="why", remediation_text="do the thing",
        remediation_cli="gcloud do-thing", categories="encryption",
    )
    db.add(f)
    db.flush()
    return f


def _make_scan(db, project, user) -> Scan:
    scan = Scan(project_id=project.id, status=ScanStatus.succeeded, triggered_by_user_id=user.id,
                pass_count=10, fail_count=5)
    db.add(scan)
    db.flush()
    return scan


def _ctx(db, project, dept, user, visible=None) -> ToolContext:
    # A real session row, because a proposal is FK-bound to one — which is
    # itself part of the design: a pending write cannot exist detached from
    # the conversation and project binding that produced it.
    session = AgentSession(user_id=user.id, project_id=project.id, title=project.project_id)
    db.add(session)
    db.flush()
    return ToolContext(
        db=db, session_id=session.id, project_pk=project.id, department_id=dept.id,
        visible_department_ids=visible if visible is not None else {dept.id},
        actor_user_id=user.id, current=_Current(user),
    )


# ── the boundary ─────────────────────────────────────────────────────────────


def test_no_tool_schema_accepts_a_project_id():
    """The load-bearing assertion of the whole feature.

    Scope is a boundary rather than a filter precisely because the model has
    no argument to put another project's id into. A filter has to be correct
    every time it runs; a missing parameter has nothing to get wrong. If this
    test ever fails, the design has quietly become a filter and every other
    guarantee here weakens with it.
    """
    for decl in agent_schemas.FUNCTION_DECLARATIONS:
        props = (decl.get("parameters") or {}).get("properties") or {}
        offending = [p for p in props if "project" in p.lower()]
        assert not offending, f"{decl['name']} exposes {offending} to the model"


def test_every_declared_tool_exists_and_every_tool_is_declared():
    """A declared-but-missing tool is a runtime error mid-conversation; an
    implemented-but-undeclared one is dead code that looks live."""
    declared = {d["name"] for d in agent_schemas.FUNCTION_DECLARATIONS}
    assert declared == set(agent_tools.REGISTRY)


def test_reads_cannot_see_another_project(db_session):
    project_a, dept_a = _make_project(db_session, "a")
    project_b, _dept_b = _make_project(db_session, "b")
    user = _make_user(db_session, "editor@example.test", dept_a.id)
    scan_a = _make_scan(db_session, project_a, user)
    scan_b = _make_scan(db_session, project_b, user)
    _make_finding(db_session, project_a, scan_a, check_id="only_in_a", resource="a1")
    _make_finding(db_session, project_b, scan_b, check_id="only_in_b", resource="b1")
    db_session.commit()

    ctx = _ctx(db_session, project_a, dept_a, user)
    summary = agent_tools.get_findings_summary(ctx)
    assert summary["total"] == 1

    checks = agent_tools.list_checks(ctx)
    assert [c["check_id"] for c in checks["checks"]] == ["only_in_a"]

    found = agent_tools.search_findings(ctx)
    assert found["total_matched"] == 1
    assert found["findings"][0]["check_id"] == "only_in_a"


def test_get_finding_by_id_cannot_cross_the_project_boundary(db_session):
    """Gate 3. Guessing an integer id from another project must not work, and
    the refusal must not confirm the row exists elsewhere."""
    project_a, dept_a = _make_project(db_session, "a")
    project_b, _dept_b = _make_project(db_session, "b")
    user = _make_user(db_session, "editor@example.test", dept_a.id)
    scan_b = _make_scan(db_session, project_b, user)
    foreign = _make_finding(db_session, project_b, scan_b, resource="b1")
    db_session.commit()

    ctx = _ctx(db_session, project_a, dept_a, user)
    with pytest.raises(ToolError) as exc:
        agent_tools.get_finding(ctx, finding_id=foreign.id)
    assert "in this project" in str(exc.value)


def test_write_tools_cannot_target_another_project(db_session):
    project_a, dept_a = _make_project(db_session, "a")
    project_b, _dept_b = _make_project(db_session, "b")
    user = _make_user(db_session, "editor@example.test", dept_a.id)
    scan_b = _make_scan(db_session, project_b, user)
    foreign = _make_finding(db_session, project_b, scan_b, resource="b1")
    db_session.commit()

    ctx = _ctx(db_session, project_a, dept_a, user)
    for call in (
        lambda: agent_tools.mute_finding(ctx, finding_id=foreign.id, mute_reason="risk_accepted"),
        lambda: agent_tools.unmute_finding(ctx, finding_id=foreign.id),
        lambda: agent_tools.set_finding_note(ctx, finding_id=foreign.id, note="x"),
    ):
        with pytest.raises(ToolError):
            call()


def test_mute_check_only_counts_the_bound_project(db_session):
    """The same check id existing in two projects must not let a mute leak
    across — the count in the banner has to be this project's alone."""
    project_a, dept_a = _make_project(db_session, "a")
    project_b, _dept_b = _make_project(db_session, "b")
    user = _make_user(db_session, "editor@example.test", dept_a.id)
    scan_a = _make_scan(db_session, project_a, user)
    scan_b = _make_scan(db_session, project_b, user)
    _make_finding(db_session, project_a, scan_a, check_id="shared", resource="a1")
    for i in range(4):
        _make_finding(db_session, project_b, scan_b, check_id="shared", resource=f"b{i}")
    db_session.commit()

    ctx = _ctx(db_session, project_a, dept_a, user)
    proposal = agent_tools.mute_check(ctx, check_id="shared", mute_reason="risk_accepted")
    assert proposal["summary"]["affected_count"] == 1


def test_viewer_cannot_reach_a_write_tool(db_session):
    """Gate 4, and unconditional — a viewer is refused before anything is
    proposed, not after."""
    project, dept = _make_project(db_session, "a")
    viewer = _make_user(db_session, "viewer@example.test", dept.id, role=Role.viewer)
    scan = _make_scan(db_session, project, viewer)
    finding = _make_finding(db_session, project, scan)
    db_session.commit()

    ctx = _ctx(db_session, project, dept, viewer)
    with pytest.raises(PermissionDeniedError):
        agent_tools.mute_finding(ctx, finding_id=finding.id, mute_reason="risk_accepted")

    # ...and the read path still works for them.
    assert agent_tools.get_findings_summary(ctx)["total"] == 1


def test_write_tools_propose_rather_than_write(db_session):
    """The propose-then-confirm gate, at its source: a write tool returns
    `awaiting_confirmation` and the row is untouched."""
    project, dept = _make_project(db_session, "a")
    editor = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, editor)
    finding = _make_finding(db_session, project, scan)
    db_session.commit()

    ctx = _ctx(db_session, project, dept, editor)
    result = agent_tools.mute_finding(
        ctx, finding_id=finding.id, mute_reason="risk_accepted", note="accepted for now"
    )
    assert result["status"] == "awaiting_confirmation"
    assert result["action_id"]

    db_session.refresh(finding)
    assert finding.muted is False
    assert finding.mute_reason is None


def test_dispatch_ignores_an_injected_project_id(db_session):
    """Defence in depth against the argument that does not exist.

    A model cannot emit `project_id` because it is not in any schema — but a
    future schema edit, or a model that hallucinates a key anyway, must not
    become a way in. `dispatch` passes arguments through by keyword, so an
    unknown one is a TypeError rather than a silent override.
    """
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    _make_finding(db_session, project, scan)
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    with pytest.raises(TypeError):
        agent_tools.dispatch(ctx, name="get_findings_summary", args={"project_id": 999})


# ── every read tool, executed ────────────────────────────────────────────────


def test_every_read_tool_executes_against_real_rows(db_session):
    """Calls each read tool once and asserts it returns.

    This exists because the boundary tests above did not: `get_project_context`
    shipped referencing `Scan.prowler_version`, a column that does not exist,
    and every test passed because none of them ever called it. A tool that
    raises is not a quiet degradation — the model reports it to the user as an
    inability to answer, so "it returns at all" is worth asserting for all of
    them, separately from what they return.
    """
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    _make_finding(db_session, project, scan, check_id="c1", resource="r1", service="compute")
    _make_finding(db_session, project, scan, check_id="c2", resource="r2", service="storage",
                  severity=Severity.critical)
    _make_finding(db_session, project, scan, check_id="c1", resource="r3", muted=True)
    db_session.add(
        ComplianceRequirement(
            framework="CIS", framework_name="CIS GCP Benchmark v3.0.0",
            requirement_id="1.1", requirement_description="Do the thing",
            check_id="c1", attributes={}, prowler_version="5.39.0",
        )
    )
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)

    assert agent_tools.get_project_context(ctx)["project_id"] == "proj-a"
    assert agent_tools.get_findings_summary(ctx)["total"] == 2
    assert agent_tools.list_services(ctx)["total_matched"] == 2
    assert agent_tools.list_checks(ctx)["total_matched"] == 2
    assert agent_tools.search_findings(ctx)["total_matched"] == 2

    first = agent_tools.search_findings(ctx)["findings"][0]["finding_id"]
    assert agent_tools.get_finding(ctx, finding_id=first)["remediation"]["cli"] == "gcloud do-thing"

    assert agent_tools.list_check_resources(ctx, check_id="c1")["total_matched"] == 1
    assert agent_tools.list_compliance_frameworks(ctx)["total"] == 1
    assert agent_tools.get_compliance_posture(
        ctx, framework="CIS", framework_name="CIS GCP Benchmark v3.0.0"
    )["total_requirements"] == 1
    assert agent_tools.get_requirements_for_check(ctx, check_id="c1")["total_matched"] == 1
    assert agent_tools.list_scan_history(ctx)["total_matched"] == 1


def test_summaries_report_what_they_excluded(db_session):
    """A muted or passing finding is hidden by default but still counted in
    `excluded`, so the agent can say "and 3 more are muted" rather than
    presenting a filtered number as the whole truth."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    _make_finding(db_session, project, scan, resource="r1")
    _make_finding(db_session, project, scan, resource="r2", muted=True)
    _make_finding(db_session, project, scan, resource="r3", status=FindingStatus.PASS)
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    summary = agent_tools.get_findings_summary(ctx)
    assert summary["total"] == 1
    assert summary["excluded"] == {"muted": 1, "passing": 1}


def test_row_caps_are_enforced_regardless_of_what_is_asked_for(db_session):
    """The model may ask for a thousand rows. It gets the ceiling, and is told
    the answer is partial — a confident summary drawn from a truncated set is
    worse than an admittedly partial one."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    for i in range(60):
        _make_finding(db_session, project, scan, check_id="bulk", resource=f"r{i}")
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    result = agent_tools.search_findings(ctx, limit=1000)
    assert result["returned"] == agent_tools.MAX_ROWS
    assert result["total_matched"] == 60
    assert result["truncated"] is True
    assert result["remaining"] == 60 - agent_tools.MAX_ROWS
    assert result["next_offset"] == agent_tools.MAX_ROWS


def test_every_list_tool_returns_the_same_paging_envelope(db_session):
    """Every list-shaped tool must describe truncation with the same six keys
    — this is what stops the shapes drifting apart again after being
    unified."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    _make_finding(db_session, project, scan, check_id="c1", resource="r1")
    db_session.add(
        ComplianceRequirement(
            framework="CIS", framework_name="CIS GCP Benchmark v3.0.0",
            requirement_id="1.1", requirement_description="Do the thing",
            check_id="c1", attributes={}, prowler_version="5.39.0",
        )
    )
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    envelope_keys = {"total_matched", "returned", "offset", "truncated", "remaining", "next_offset"}

    results = [
        agent_tools.list_checks(ctx),
        agent_tools.search_findings(ctx),
        agent_tools.list_check_resources(ctx, check_id="c1"),
        agent_tools.list_services(ctx),
        agent_tools.get_requirements_for_check(ctx, check_id="c1"),
    ]
    for result in results:
        assert envelope_keys <= result.keys()


def test_next_offset_walks_the_whole_list(db_session):
    """A truncated result's `next_offset` must be usable to fetch the rest —
    this is the fix for "show me the rest" being a dead end."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    for i in range(120):
        _make_finding(db_session, project, scan, check_id="bulk", resource=f"r{i}")
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    collected = set()
    offset = 0
    previous_remaining = None
    while True:
        result = agent_tools.list_check_resources(ctx, check_id="bulk", limit=50, offset=offset)
        collected.update(r["finding_id"] for r in result["resources"])
        if previous_remaining is not None:
            assert result["remaining"] < previous_remaining
        previous_remaining = result["remaining"]
        if result["next_offset"] is None:
            assert result["truncated"] is False
            break
        offset = result["next_offset"]

    assert len(collected) == 120


def test_a_complete_list_is_not_marked_truncated(db_session):
    """Guards the off-by-one that would make every complete list look
    truncated."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    for i in range(3):
        _make_finding(db_session, project, scan, check_id="c1", resource=f"r{i}")
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    result = agent_tools.list_check_resources(ctx, check_id="c1", limit=50)
    assert result["truncated"] is False
    assert result["remaining"] == 0
    assert result["next_offset"] is None


def test_offset_past_the_end_returns_an_empty_page_not_an_error(db_session):
    """A model that over-pages must get an empty page, not a crash."""
    project, dept = _make_project(db_session, "a")
    user = _make_user(db_session, "editor@example.test", dept.id)
    scan = _make_scan(db_session, project, user)
    for i in range(3):
        _make_finding(db_session, project, scan, check_id="c1", resource=f"r{i}")
    db_session.commit()

    ctx = _ctx(db_session, project, dept, user)
    result = agent_tools.list_check_resources(ctx, check_id="c1", offset=999)
    assert result["returned"] == 0
    assert result["truncated"] is False
