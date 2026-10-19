"""The agent's entire reach into the database.

Fifteen named functions. **There is no SQL tool, no query builder, and no
escape hatch** — a model that wants a number it cannot get from one of these
has to say so instead of inventing a query.

The load-bearing design point, and the reason this is a boundary rather than a
filter:

    `project_id` appears in NO tool's argument schema.

Scope is injected by the executor from `ToolContext`, which is assembled by
the API layer from the session's immutable binding. A hallucinated project id
cannot be passed because there is no parameter to pass it in; a user asking
"now show me the other project" produces a call that is still scoped, and the
model has to answer that it cannot. Gating an argument the model *can* set is
a filter and depends on the gate being correct every time. Removing the
argument is a boundary and depends on nothing.

Four gates, in order:

1.  Session creation checks `require_department_role(viewer)`. No session row
    exists without it (`services/agent.py`).
2.  Every read injects both `project_id=ctx.project_pk` **and** the caller's
    real `visible_department_ids`. Two independent narrowings; a bug in one
    cannot widen past the other.
3.  Every id-addressed tool re-asserts `finding.project_id == ctx.project_pk`
    after loading, and answers "not in this project" — never "denied", which
    would confirm the row exists elsewhere.
4.  Every write re-checks `require_department_role(editor)` at call time,
    **unconditionally**. Not the `if department_id is not None:` shape used by
    the human endpoints in `routers/findings.py`: that skips the check
    entirely on a null department, which is fail-open. It is unexploitable
    there only because `GcpOrganization.department_id` is NOT NULL, and
    inheriting the shape here would be inheriting a latent bug.

Writes never write. A write tool validates, stores a `PendingAction`, and
returns `awaiting_confirmation`; `services/agent.py::apply_pending_action` is
the only thing that reaches `services/findings.py`. See `models/agent.py`.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections import Counter, defaultdict
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import observability
from app.models.compliance_requirement import ComplianceRequirement
from app.models.department import Department
from app.models.finding import Finding, FindingStatus, MuteReason, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan
from app.models.user_department_role import Role
from app.services import compliance as compliance_service
from app.services import findings as findings_service
from app.services.errors import InvalidRequestError
from app.services.rbac import require_department_role

# Hard ceilings, applied to whatever the model asked for. A tool that
# truncates says so (`total_matched` beside `returned`), so the agent reports
# a partial answer as partial instead of concluding from it — a summary drawn
# confidently from the first 50 of 4,000 rows is worse than no summary.
MAX_ROWS = 50
# Raised from 100 so a typical check fits in one call — a busy check can exceed
# 100 resources, and a ceiling just under the common case is the worst place
# to put one.
MAX_RESOURCE_ROWS = 150
MAX_SCAN_HISTORY = 10

# Non-PASS, non-vanished. The default lens for every aggregate: a posture
# question is about what is currently wrong, and PASS rows outnumber FAIL
# rows several times over in a large scan.
_ACTIONABLE = (FindingStatus.FAIL, FindingStatus.MANUAL)

SEVERITY_ORDER = [s.value for s in Severity]


class ToolContext:
    """Everything a tool is allowed to know about who is asking.

    Assembled by the API layer from the session row. Deliberately not a
    dataclass the model can influence any part of — every field here comes
    from the database or the authenticated request, never from tool arguments.
    """

    def __init__(
        self,
        *,
        db: Session,
        session_id: int,
        project_pk: int,
        department_id: int,
        visible_department_ids: set[int] | str,
        actor_user_id: int,
        current,
    ):
        self.db = db
        self.session_id = session_id
        self.project_pk = project_pk
        self.department_id = department_id
        self.visible_department_ids = visible_department_ids
        self.actor_user_id = actor_user_id
        self.current = current


class ToolError(InvalidRequestError):
    """A tool could not answer. Surfaced back to the model as a normal tool
    result rather than raised through the request, so the conversation can
    recover ("that check id doesn't exist here — did you mean ...") instead of
    the whole turn failing."""


# ── scoping helpers ──────────────────────────────────────────────────────────


def _scoped_findings_query(ctx: ToolContext, *, include_muted: bool, include_passing: bool):
    """The single place the project binding becomes SQL.

    Every aggregate below goes through this, so there is one definition of
    "this session's findings" rather than one per tool.
    """
    stmt = (
        select(Finding)
        .join(Project, Project.id == Finding.project_id)
        .join(GcpOrganization, GcpOrganization.id == Project.gcp_organization_id)
        .where(Finding.project_id == ctx.project_pk)
    )
    # Gate 2's second narrowing. Redundant with the project filter by
    # construction — and kept precisely because "redundant by construction" is
    # a property of today's code, not a guarantee.
    if ctx.visible_department_ids != "ALL":
        stmt = stmt.where(GcpOrganization.department_id.in_(ctx.visible_department_ids))
    if not include_muted:
        stmt = stmt.where(Finding.muted.is_(False))
    if not include_passing:
        stmt = stmt.where(Finding.status.in_(_ACTIONABLE))
    return stmt


def _finding_in_scope(ctx: ToolContext, finding_id: int) -> Finding:
    """Gate 3. Loads by id, then proves the row belongs to this session's
    project before anything else may touch it."""
    finding = ctx.db.get(Finding, finding_id)
    if finding is None or finding.project_id != ctx.project_pk:
        raise ToolError(
            f"no finding with id {finding_id} in this project — the session is "
            "bound to one project and cannot reach outside it"
        )
    return finding


def _require_editor(ctx: ToolContext) -> None:
    """Gate 4. Unconditional by design — see the module docstring."""
    require_department_role(
        ctx.db, ctx.current, department_id=ctx.department_id, minimum=Role.editor
    )


def _clamp(value: Any, default: int, ceiling: int) -> int:
    try:
        n = int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
    return max(1, min(n, ceiling))


def _paged(
    rows: list, *, limit: Any, offset: Any, default: int, ceiling: int
) -> tuple[list, dict]:
    """Slice `rows` and describe the slice in the one envelope every list tool
    returns.

    Written once and shared because the tools previously each described
    truncation differently — three names for the total, one tool with no
    `truncated` key at all — and a model cannot learn one rule from seven
    different shapes.

    `next_offset` is the part that matters most. Reporting that a list is
    truncated is only half an answer if the model has no way to fetch the
    rest; handing it the exact offset to ask for turns a dead end into a
    first page.
    """
    limit = _clamp(limit, default, ceiling)
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0

    page = rows[offset : offset + limit]
    remaining = max(0, len(rows) - (offset + len(page)))
    envelope = {
        "total_matched": len(rows),
        "returned": len(page),
        "offset": offset,
        "truncated": remaining > 0,
        "remaining": remaining,
        "next_offset": offset + len(page) if remaining else None,
    }
    return page, envelope


def _severity_breakdown(rows) -> dict[str, int]:
    counts = Counter(f.severity.value for f in rows)
    return {s: counts.get(s, 0) for s in SEVERITY_ORDER if counts.get(s, 0)}


# ── Band A: orient ───────────────────────────────────────────────────────────


def get_project_context(ctx: ToolContext) -> dict:
    """No arguments — the session already knows which project it is bound to.

    Called first in practice, and the reason the agent never opens by asking
    the user which project they mean. It also states the boundary out loud, so
    the model's own context carries "I can see exactly one project" rather
    than inferring it from tools that quietly refuse.
    """
    project = ctx.db.get(Project, ctx.project_pk)
    org = ctx.db.get(GcpOrganization, project.gcp_organization_id)
    department = ctx.db.get(Department, org.department_id)

    latest = ctx.db.execute(
        select(Scan)
        .where(Scan.project_id == ctx.project_pk)
        .order_by(Scan.id.desc())
        .limit(1)
    ).scalar_one_or_none()

    total_findings = ctx.db.execute(
        select(func.count(Finding.id)).where(Finding.project_id == ctx.project_pk)
    ).scalar_one()

    return {
        "project_id": project.project_id,
        "organization": {"org_id": org.org_id, "name": org.name},
        "department": department.name if department else None,
        "target_service_account": project.target_sa_email,
        "total_findings_stored": total_findings,
        "latest_scan": None
        if latest is None
        else {
            "scan_id": latest.id,
            "status": latest.status.value,
            "triggered_at": latest.triggered_at.isoformat() if latest.triggered_at else None,
            "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
            "pass_count": latest.pass_count,
            "fail_count": latest.fail_count,
            "compliance_drift_detected": latest.compliance_drift_detected,
        },
        "scope_note": (
            "This conversation is bound to this one project. No tool can read or "
            "modify any other project."
        ),
    }


def get_findings_summary(
    ctx: ToolContext, *, include_muted: bool = False, include_passing: bool = False
) -> dict:
    """The overview. Same shape the Findings Overview screen computes in
    `lib/findings-aggregates.ts`, computed here so the agent's numbers and the
    screen's numbers come from one definition."""
    rows = list(
        ctx.db.execute(
            _scoped_findings_query(ctx, include_muted=include_muted, include_passing=include_passing)
        ).scalars()
    )
    all_rows = list(
        ctx.db.execute(
            _scoped_findings_query(ctx, include_muted=True, include_passing=True)
        ).scalars()
    )
    by_service = Counter(f.service_name for f in rows)
    return {
        "scope": {"include_muted": include_muted, "include_passing": include_passing},
        "total": len(rows),
        "by_severity": _severity_breakdown(rows),
        "by_status": dict(Counter(f.status.value for f in rows)),
        "distinct_checks": len({f.check_id for f in rows}),
        "distinct_services": len(by_service),
        "top_services": [
            {"service_name": name, "count": count} for name, count in by_service.most_common(10)
        ],
        "excluded": {
            "muted": sum(1 for f in all_rows if f.muted),
            "passing": sum(1 for f in all_rows if f.status == FindingStatus.PASS),
        },
    }


def list_services(
    ctx: ToolContext,
    *,
    include_muted: bool = False,
    include_passing: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """Where the risk is concentrated. Per service, total plus a severity
    breakdown — the treemap and heatmap on the overview screen, as data."""
    rows = list(
        ctx.db.execute(
            _scoped_findings_query(ctx, include_muted=include_muted, include_passing=include_passing)
        ).scalars()
    )
    grouped: dict[str, list] = defaultdict(list)
    for f in rows:
        grouped[f.service_name].append(f)
    services = [
        {
            "service_name": name,
            "count": len(items),
            "by_severity": _severity_breakdown(items),
        }
        for name, items in grouped.items()
    ]
    services.sort(key=lambda s: -s["count"])
    page, envelope = _paged(services, limit=limit, offset=offset, default=MAX_ROWS, ceiling=MAX_ROWS)
    return {**envelope, "services": page}


def list_checks(
    ctx: ToolContext,
    *,
    severity: list[str] | None = None,
    status: list[str] | None = None,
    service_name: list[str] | None = None,
    include_muted: bool = False,
    sort: str = "resource_count",
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """Check-level rollup — **the unit that actually matters here.**

    One check emits one finding per resource, so "BigQuery datasets not using
    CMEK" is one decision and forty rows. Advice pitched at row level reads as
    a list; advice pitched at check level is actionable, and it is also the
    granularity `mute_check` operates on.
    """
    stmt = _scoped_findings_query(ctx, include_muted=include_muted, include_passing=False)
    if severity:
        stmt = stmt.where(Finding.severity.in_([Severity(s) for s in severity]))
    if status:
        stmt = stmt.where(Finding.status.in_([FindingStatus(s) for s in status]))
    if service_name:
        stmt = stmt.where(Finding.service_name.in_(service_name))
    rows = list(ctx.db.execute(stmt).scalars())

    grouped: dict[str, list] = defaultdict(list)
    for f in rows:
        grouped[f.check_id].append(f)

    # Muted rows are counted per check even when excluded from the group
    # itself, so the agent can see "12 affected, 40 already muted" and not
    # propose muting a check that is essentially already handled.
    muted_counts = dict(
        ctx.db.execute(
            select(Finding.check_id, func.count(Finding.id))
            .where(Finding.project_id == ctx.project_pk, Finding.muted.is_(True))
            .group_by(Finding.check_id)
        ).all()
    )

    checks = [
        {
            "check_id": check_id,
            "check_title": items[0].check_title,
            "severity": items[0].severity.value,
            "service_name": items[0].service_name,
            "affected_resources": len(items),
            "already_muted": muted_counts.get(check_id, 0),
        }
        for check_id, items in grouped.items()
    ]
    if sort == "severity":
        checks.sort(key=lambda c: (SEVERITY_ORDER.index(c["severity"]), -c["affected_resources"]))
    else:
        checks.sort(key=lambda c: (-c["affected_resources"], SEVERITY_ORDER.index(c["severity"])))

    page, envelope = _paged(checks, limit=limit, offset=offset, default=MAX_ROWS, ceiling=MAX_ROWS)
    return {**envelope, "checks": page}


# ── Band B: drill ────────────────────────────────────────────────────────────


def search_findings(
    ctx: ToolContext,
    *,
    severity: list[str] | None = None,
    status: list[str] | None = None,
    muted: bool | None = None,
    mute_reason: list[str] | None = None,
    service_name: list[str] | None = None,
    subservice_name: list[str] | None = None,
    region: list[str] | None = None,
    resource_type: list[str] | None = None,
    check_id: list[str] | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """Row-level search, through `services/findings.py::list_findings` itself.

    The filter set is that function's own, minus `project_id` — which the
    executor supplies. Reusing the one function rather than rebuilding the
    query is what stops the agent's idea of a filter drifting from the
    screen's; a "high severity" that means something different in chat than in
    the table is the failure mode worth spending an import on.
    """
    # **Absent means the default lens; explicit means exactly what was asked.**
    #
    # Every aggregate tool above hides muted and passing findings unless told
    # otherwise. Without the same rule here, `get_findings_summary` and
    # `search_findings` answer the same question with different numbers, and
    # the model has no way to know which one to trust — it will happily report
    # "2 problems" in one sentence and list three rows in the next. This is
    # the same failure the Findings Overview screen fixed for itself (see its
    # comment on one scope applied once); the agent needs it for the same
    # reason and it must be the same lens.
    #
    # An explicit `muted` or `status` still wins outright, so "show me what's
    # muted" works exactly as asked.
    effective_statuses = (
        [FindingStatus(s) for s in status] if status else list(_ACTIONABLE)
    )

    rows = findings_service.list_findings(
        ctx.db,
        # Gate 2, both narrowings, on the shared read path.
        visible_department_ids=ctx.visible_department_ids,
        project_id=ctx.project_pk,
        severities=[Severity(s) for s in severity] if severity else None,
        statuses=effective_statuses,
        muted=[muted] if muted is not None else [False],
        mute_reasons=[MuteReason(r) for r in mute_reason] if mute_reason else None,
        service_names=service_name,
        subservice_names=subservice_name,
        regions=region,
        resource_types=resource_type,
        check_ids=check_id,
        search=search,
    )
    page, envelope = _paged(rows, limit=limit, offset=offset, default=25, ceiling=MAX_ROWS)
    return {
        **envelope,
        "scope": {
            "statuses": [s.value for s in effective_statuses],
            "muted": muted if muted is not None else False,
        },
        "findings": [
            {
                "finding_id": f.id,
                "check_id": f.check_id,
                "check_title": f.check_title,
                "severity": f.severity.value,
                "status": f.status.value,
                "service_name": f.service_name,
                "resource_name": f.resource_name,
                "region": f.region,
                "muted": f.muted,
                "mute_reason": f.mute_reason.value if f.mute_reason else None,
            }
            for f in page
        ],
    }


def get_finding(ctx: ToolContext, *, finding_id: int) -> dict:
    """One finding in full, including Prowler's own remediation content.

    That content is carried verbatim from the scanner through the importer.
    The agent quotes it; it must never author a `gcloud` command of its own —
    the same rule `services/reports.py` already enforces for generated
    reports, and for the same reason: a model-invented remediation command run
    against a customer's production project is the worst outcome this feature
    has available to it.
    """
    f = _finding_in_scope(ctx, finding_id)
    return {
        "finding_id": f.id,
        "check_id": f.check_id,
        "check_title": f.check_title,
        "severity": f.severity.value,
        "status": f.status.value,
        "status_extended": f.status_extended,
        "service_name": f.service_name,
        "subservice_name": f.subservice_name,
        "region": f.region,
        "resource_type": f.resource_type,
        "resource_name": f.resource_name,
        "resource_uid": f.resource_uid,
        "finding_uid": f.finding_uid,
        "description": f.description,
        "risk": f.risk,
        "remediation": {
            "text": f.remediation_text,
            "url": f.remediation_url,
            "cli": f.remediation_cli,
            "terraform": f.remediation_terraform,
            "iac": f.remediation_iac,
        },
        "categories": f.categories,
        "muted": f.muted,
        "mute_reason": f.mute_reason.value if f.mute_reason else None,
        "note": f.note,
        "first_seen_at": f.first_seen_at.isoformat(),
        "updated_at": f.updated_at.isoformat(),
        "remediation_note": (
            "Quote these remediation fields verbatim. Never compose a gcloud, "
            "Terraform or CLI command that is not present here."
        ),
    }


def list_check_resources(
    ctx: ToolContext,
    *,
    check_id: str,
    status: list[str] | None = None,
    include_muted: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> dict:
    """Every resource one check hit.

    Named for the check, not the finding, on purpose: a *finding* in this
    schema is already one resource, so the thing with many assets underneath
    it is the check. Getting that vocabulary right in the tool name is most of
    what stops the model conflating the two.
    """
    stmt = _scoped_findings_query(ctx, include_muted=include_muted, include_passing=True).where(
        Finding.check_id == check_id
    )
    if status:
        stmt = stmt.where(Finding.status.in_([FindingStatus(s) for s in status]))
    rows = list(ctx.db.execute(stmt).scalars())
    if not rows:
        raise ToolError(
            f"no findings for check '{check_id}' in this project — call list_checks "
            "to see which check ids exist here"
        )
    page, envelope = _paged(rows, limit=limit, offset=offset, default=50, ceiling=MAX_RESOURCE_ROWS)
    return {
        **envelope,
        "check_id": check_id,
        "check_title": rows[0].check_title,
        "severity": rows[0].severity.value,
        "resources": [
            {
                "finding_id": f.id,
                "resource_uid": f.resource_uid,
                "resource_name": f.resource_name,
                "resource_type": f.resource_type,
                "region": f.region,
                "status": f.status.value,
                "muted": f.muted,
            }
            for f in page
        ],
    }


# ── Band C: correlate ────────────────────────────────────────────────────────


def list_compliance_frameworks(ctx: ToolContext) -> dict:
    """Exists so the model discovers exact framework names rather than
    guessing them. The rulebook holds four CIS versions sharing one
    `framework` value ("CIS") and differing only in `framework_name`
    ("... Benchmark v2.0.0" vs "v3.0.0") — precisely the string a model
    invents wrong."""
    frameworks = compliance_service.list_frameworks(ctx.db, project_id=ctx.project_pk)
    return {"total": len(frameworks), "frameworks": frameworks}


def get_compliance_posture(
    ctx: ToolContext, *, framework: str, framework_name: str, include_muted: bool = False
) -> dict:
    """Live requirement-level rollup for one framework, through
    `services/compliance.py::compliance_report` — nothing precomputed, so it is
    never stale relative to the findings behind it."""
    report = compliance_service.compliance_report(
        ctx.db,
        project_id=ctx.project_pk,
        framework=framework,
        framework_name=framework_name,
        include_muted=include_muted,
    )
    requirements = report.get("requirements", [])
    failing = [r for r in requirements if r["status"] == "fail"]
    return {
        "framework": report.get("framework"),
        "framework_name": report.get("framework_name"),
        "score_percent": report.get("score_percent"),
        "total_requirements": len(requirements),
        "by_status": dict(Counter(r["status"] for r in requirements)),
        "failing_requirements": [
            {
                "requirement_id": r["requirement_id"],
                "description": r["requirement_description"],
                "check_ids": r["check_ids"],
            }
            for r in failing[:MAX_ROWS]
        ],
        "failing_total": len(failing),
        "failing_returned": min(len(failing), MAX_ROWS),
        "failing_truncated": len(failing) > MAX_ROWS,
    }


def get_requirements_for_check(
    ctx: ToolContext, *, check_id: str, limit: int | None = None, offset: int = 0
) -> dict:
    """Which framework requirements one check satisfies.

    The tool that turns "mute this" into "muting this drops CIS 3.0
    requirement 1.14 to not_assessed" — the difference between a chat that
    saves clicks and one that improves the decision. Deliberately consulted
    before any mute proposal; the system instruction says so.
    """
    rows = ctx.db.execute(
        select(
            ComplianceRequirement.framework,
            ComplianceRequirement.framework_name,
            ComplianceRequirement.requirement_id,
            ComplianceRequirement.requirement_description,
        )
        .where(ComplianceRequirement.check_id == check_id)
        .order_by(ComplianceRequirement.framework_name, ComplianceRequirement.requirement_id)
    ).all()
    page, envelope = _paged(rows, limit=limit, offset=offset, default=MAX_ROWS, ceiling=MAX_ROWS)
    return {
        **envelope,
        "check_id": check_id,
        "requirements": [
            {
                "framework": f,
                "framework_name": fn,
                "requirement_id": rid,
                "description": desc,
            }
            for f, fn, rid, desc in page
        ],
        "note": (
            "Empty means the rulebook maps no framework requirement to this check, "
            "not that the check is unimportant."
        ),
    }


def list_scan_history(ctx: ToolContext, *, limit: int | None = None) -> dict:
    """Recent scans for this project — enough to answer "when was this last
    checked" and "did the totals move".

    Scan-level counters only. A true per-finding diff between scans is not
    possible against this schema (it stores current state plus
    `first_seen_at`, not history) and is deliberately not faked; the agent can
    say a finding is new by its `first_seen_at`, and nothing more.
    """
    total = ctx.db.execute(
        select(func.count(Scan.id)).where(Scan.project_id == ctx.project_pk)
    ).scalar_one()
    limit = _clamp(limit, 5, MAX_SCAN_HISTORY)
    rows = list(
        ctx.db.execute(
            select(Scan)
            .where(Scan.project_id == ctx.project_pk)
            .order_by(Scan.id.desc())
            .limit(limit)
        ).scalars()
    )
    remaining = max(0, total - len(rows))
    return {
        "total_matched": total,
        "returned": len(rows),
        "offset": 0,
        "truncated": remaining > 0,
        "remaining": remaining,
        # No offset parameter: scan history is newest-first and small by
        # design, so paging deeper into it is not a question anyone asks.
        "next_offset": None,
        "scans": [
            {
                "scan_id": s.id,
                "status": s.status.value,
                "triggered_at": s.triggered_at.isoformat() if s.triggered_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "pass_count": s.pass_count,
                "fail_count": s.fail_count,
                "compliance_drift_detected": s.compliance_drift_detected,
            }
            for s in rows
        ],
    }


# ── Band D: act — these PROPOSE, they never write ────────────────────────────
#
# Each returns `awaiting_confirmation` plus a summary the UI renders as a
# banner. The write itself happens in `services/agent.py::apply_pending_action`
# and only after a human confirms. See models/agent.py for why the validated
# arguments are stored server-side rather than travelling back with the
# confirmation.


def _propose(ctx: ToolContext, *, tool_name: str, args: dict, summary: dict) -> dict:
    from app.services import agent as agent_service

    action = agent_service.create_pending_action(
        ctx.db,
        session_id=ctx.session_id,
        user_id=ctx.actor_user_id,
        project_id=ctx.project_pk,
        tool_name=tool_name,
        args=args,
        summary=summary,
    )
    return {
        "status": "awaiting_confirmation",
        "action_id": action.id,
        "summary": summary,
        "note": (
            "Nothing has been changed yet. The user must confirm this in the "
            "interface before it takes effect. Tell them what you have prepared "
            "and that it is waiting for their confirmation — do not claim it is done."
        ),
    }


def mute_finding(
    ctx: ToolContext, *, finding_id: int, mute_reason: str, note: str | None = None
) -> dict:
    _require_editor(ctx)
    f = _finding_in_scope(ctx, finding_id)
    reason = MuteReason(mute_reason)
    if f.muted:
        raise ToolError(f"finding {finding_id} is already muted ({f.mute_reason.value})")
    return _propose(
        ctx,
        tool_name="mute_finding",
        args={"finding_id": finding_id, "mute_reason": reason.value, "note": note},
        summary={
            "action": "Mute one finding",
            "check_id": f.check_id,
            "check_title": f.check_title,
            "severity": f.severity.value,
            "resource_name": f.resource_name,
            "mute_reason": reason.value,
            "note": note,
            "affected_count": 1,
        },
    )


def unmute_finding(ctx: ToolContext, *, finding_id: int, note: str | None = None) -> dict:
    """A separate tool rather than a `muted: bool` flag on the one above. A
    boolean is the shape that gets flipped by accident, and the two directions
    deserve different confirmation copy."""
    _require_editor(ctx)
    f = _finding_in_scope(ctx, finding_id)
    if not f.muted:
        raise ToolError(f"finding {finding_id} is not muted")
    return _propose(
        ctx,
        tool_name="unmute_finding",
        args={"finding_id": finding_id, "note": note},
        summary={
            "action": "Unmute one finding",
            "check_id": f.check_id,
            "check_title": f.check_title,
            "severity": f.severity.value,
            "resource_name": f.resource_name,
            "current_mute_reason": f.mute_reason.value if f.mute_reason else None,
            "note": note,
            "affected_count": 1,
        },
    )


def mute_check(
    ctx: ToolContext, *, check_id: str, mute_reason: str, note: str | None = None
) -> dict:
    """The highest-leverage tool and the most dangerous one — one call can
    touch hundreds of rows.

    The count and a resource sample are computed **now**, at proposal time, so
    the banner states the real blast radius rather than an estimate. Already-
    muted findings are excluded here exactly as
    `services/findings.py::mute_by_check` excludes them, so the number shown is
    the number that will change.
    """
    _require_editor(ctx)
    reason = MuteReason(mute_reason)
    rows = list(
        ctx.db.execute(
            select(Finding).where(
                Finding.project_id == ctx.project_pk,
                Finding.check_id == check_id,
                Finding.muted.is_(False),
            )
        ).scalars()
    )
    if not rows:
        raise ToolError(
            f"no unmuted findings for check '{check_id}' in this project — nothing to mute"
        )
    return _propose(
        ctx,
        tool_name="mute_check",
        args={"check_id": check_id, "mute_reason": reason.value, "note": note},
        summary={
            "action": "Mute every unmuted finding for one check",
            "check_id": check_id,
            "check_title": rows[0].check_title,
            "severity": rows[0].severity.value,
            "mute_reason": reason.value,
            "note": note,
            "affected_count": len(rows),
            "sample_resources": [f.resource_name for f in rows[:8]],
        },
    )


def set_finding_note(ctx: ToolContext, *, finding_id: int, note: str) -> dict:
    """Annotate without touching mute state."""
    _require_editor(ctx)
    f = _finding_in_scope(ctx, finding_id)
    return _propose(
        ctx,
        tool_name="set_finding_note",
        args={"finding_id": finding_id, "note": note},
        summary={
            "action": "Set a note on one finding",
            "check_id": f.check_id,
            "check_title": f.check_title,
            "resource_name": f.resource_name,
            "previous_note": f.note,
            "note": note,
            "affected_count": 1,
        },
    )


WRITE_TOOLS = frozenset({"mute_finding", "unmute_finding", "mute_check", "set_finding_note"})

REGISTRY: dict[str, Callable[..., dict]] = {
    "get_project_context": get_project_context,
    "get_findings_summary": get_findings_summary,
    "list_services": list_services,
    "list_checks": list_checks,
    "search_findings": search_findings,
    "get_finding": get_finding,
    "list_check_resources": list_check_resources,
    "list_compliance_frameworks": list_compliance_frameworks,
    "get_compliance_posture": get_compliance_posture,
    "get_requirements_for_check": get_requirements_for_check,
    "list_scan_history": list_scan_history,
    "mute_finding": mute_finding,
    "unmute_finding": unmute_finding,
    "mute_check": mute_check,
    "set_finding_note": set_finding_note,
}


def dispatch(ctx: ToolContext, *, name: str, args: dict) -> dict:
    """The one entry point. Every call the model makes lands here, which is
    why `project_id` never needs to be filtered out of `args` — it was never
    in the schema, so it cannot be there to filter.

    It is also the one place every tool call can be traced, for exactly the
    same reason: instrumenting the fifteen functions individually would leave
    the sixteenth untraced the day someone adds it.
    """
    with observability.observation(
        f"tool · {name}",
        as_type="tool",
        input=args or {},
        # The scope the call actually ran under, not the scope it asked for —
        # the injected binding is the whole security story, and a trace that
        # showed only the model's arguments would not show it at all.
        metadata={"project_pk": ctx.project_pk, "is_write": name in WRITE_TOOLS},
    ) as span:
        fn = REGISTRY.get(name)
        if fn is None:
            span.update(level="WARNING", status_message=f"unknown tool '{name}'")
            raise ToolError(f"unknown tool '{name}'")
        clean = {k: v for k, v in (args or {}).items() if v is not None}
        result = fn(ctx, **clean)
        span.update(output=result, metadata=_result_shape(result))
        return result


def _result_shape(result) -> dict:
    """Truncation flags, lifted where a reader will see them.

    Every paged tool already reports `returned` beside `total_matched` so a
    model reasons from a partial answer as partial. Surfacing the same fact in
    the span's metadata is what lets "the agent concluded that from the first
    50 of 4,000 rows" be *noticed* rather than reconstructed from the payload
    after someone already doubted the report.
    """
    try:
        if not isinstance(result, dict):
            return {}
        keys = ("returned", "total_matched", "truncated", "failing_truncated", "next_offset")
        return {k: result[k] for k in keys if k in result}
    except Exception:  # noqa: BLE001 — tracing must never fail a tool call
        return {}


# ── the report agent's narrower door ─────────────────────────────────────────

READ_TOOLS = frozenset(REGISTRY) - WRITE_TOOLS


def dispatch_readonly(ctx: ToolContext, *, name: str, args: dict) -> dict:
    """`dispatch`, with every write tool refused.

    Used by the deep-report graph (`app/agents/`), which investigates a project
    in order to write about it and must never change it. Report generation is
    unattended — there is no banner for a human to confirm and no session to
    attach a `PendingAction` to — so a write tool reached from here would be
    either an unconfirmed mutation or a crash. Neither is acceptable, and a
    refusal that says so is better than either.

    This is the second of two independent gates. The first is that the graph
    declares only the read subset of `FUNCTION_DECLARATIONS` to the model, so
    a write tool is not offered in the first place. This one covers the case
    where the two lists drift apart — a tool added to the registry as a read
    tool and later made to write, say — and it is the gate that holds if the
    declaration list is ever built wrongly.
    """
    if name not in READ_TOOLS:
        raise ToolError(
            f"'{name}' is not available while generating a report — report generation "
            "reads findings, it never changes them"
        )
    return dispatch(ctx, name=name, args=args)
