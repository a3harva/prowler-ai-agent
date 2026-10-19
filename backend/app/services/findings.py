"""Read path for `findings`, plus the one write this module owns: the human
triage overlay (`muted`, `mute_reason`, `note`). Scan-derived fields are
`services/importer.py`'s exclusively — this file never touches them, the
same split `services/scans.py` and `services/importer.py` make for scans.
"""

from __future__ import annotations

import csv
import datetime
import io

from sqlalchemy import case, or_, select
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus, MuteReason, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.services import audit
from app.services.rbac import ALL_DEPARTMENTS, is_department_visible
from app.services.errors import NotFoundError

# Most-severe-first — the order a triage screen wants by default, and the
# tie-break used both by the list endpoint and by CSV export so the two never
# disagree about which row comes first.
_SEVERITY_RANK = case(
    {severity.value: rank for rank, severity in enumerate(Severity)},
    value=Finding.severity,
)


class FindingNotFoundError(NotFoundError):
    def __init__(self, finding_id: int):
        super().__init__(f"no finding with id {finding_id}")
        self.finding_id = finding_id


def get_finding(
    db: Session, *, finding_id: int, visible_department_ids: set[int] | str
) -> Finding:
    """Single-record read for the finding detail page, scoped to what the
    caller may see.

    This used to take no scope at all, on the reasoning that `list_findings`
    was scoped and a direct-by-id lookup need not be — matching
    `services/scans.py::get_scan`'s own precedent. That reasoning was wrong,
    and in a security product it was the wrong way round: it meant any signed
    -in user could read any finding in the estate by walking integer ids, past
    the RBAC model the list endpoint spends a join enforcing. Both `get_scan`
    and `get_report` carried the identical hole and are fixed the same way.

    `visible_department_ids` is **required, not optional with a permissive
    default**. An optional scope is the shape that gets forgotten at one call
    site and silently reopens the hole; a required one cannot be. Code that
    genuinely has no user — the Celery worker, `services/compliance.py` —
    passes `ALL_DEPARTMENTS` explicitly, so every deliberately unscoped read
    is greppable rather than invisible.

    An out-of-scope finding raises `FindingNotFoundError`, not a permission
    error. A 403 here would confirm that the id exists and that someone else
    owns it, which is a membership oracle over the whole estate; 404 says only
    "not yours to see" and leaks nothing.
    """
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)
    if not is_department_visible(department_id_for_finding(db, finding_id), visible_department_ids):
        raise FindingNotFoundError(finding_id)
    return finding


def list_findings(
    db: Session,
    *,
    visible_department_ids: set[int] | str,
    project_id: int | None = None,
    severities: list[Severity] | None = None,
    statuses: list[FindingStatus] | None = None,
    muted: list[bool] | None = None,
    mute_reasons: list[MuteReason] | None = None,
    service_names: list[str] | None = None,
    subservice_names: list[str] | None = None,
    regions: list[str] | None = None,
    resource_types: list[str] | None = None,
    check_ids: list[str] | None = None,
    search: str | None = None,
) -> list[Finding]:
    """The one query behind both the on-screen table and `export_findings_csv`
    (which calls this directly, filters and all) — so the two can never
    drift: a customer-bound export that silently ignores a filter the
    screen applied is the failure mode this module exists to prevent."""
    stmt = (
        select(Finding)
        .join(Project, Project.id == Finding.project_id)
        .join(GcpOrganization, GcpOrganization.id == Project.gcp_organization_id)
    )
    if project_id is not None:
        stmt = stmt.where(Finding.project_id == project_id)
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(GcpOrganization.department_id.in_(visible_department_ids))
    if severities:
        stmt = stmt.where(Finding.severity.in_(severities))
    if statuses:
        stmt = stmt.where(Finding.status.in_(statuses))
    if muted:
        stmt = stmt.where(Finding.muted.in_(muted))
    if mute_reasons:
        stmt = stmt.where(Finding.mute_reason.in_(mute_reasons))
    if service_names:
        stmt = stmt.where(Finding.service_name.in_(service_names))
    if subservice_names:
        stmt = stmt.where(Finding.subservice_name.in_(subservice_names))
    if regions:
        stmt = stmt.where(Finding.region.in_(regions))
    if resource_types:
        stmt = stmt.where(Finding.resource_type.in_(resource_types))
    if check_ids:
        stmt = stmt.where(Finding.check_id.in_(check_ids))
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(Finding.resource_name.ilike(pattern), Finding.check_title.ilike(pattern))
        )
    stmt = stmt.order_by(_SEVERITY_RANK, Finding.id)
    return list(db.execute(stmt).scalars())


_EXPORT_COLUMNS = [
    "project_id",
    "check_id",
    "check_title",
    "severity",
    "status",
    "status_extended",
    "service_name",
    "subservice_name",
    "region",
    "resource_type",
    "resource_name",
    "resource_uid",
    "finding_uid",
    "muted",
    "mute_reason",
    "note",
    "first_seen_at",
    "updated_at",
]


def export_findings_csv(db: Session, *, visible_department_ids: set[int] | str, **filters) -> str:
    """Current stored state under the active filters — never the original
    scanner output, which is why this reads the `findings` table (through
    the exact same `list_findings` call, filters and all, that the screen
    uses) rather than anything on disk. The mute overlay (`muted`,
    `mute_reason`, `note`) is included so the file is what a customer
    actually needs, not a re-hash of the raw CSV they could already ask
    for. `**filters` forwards whatever `list_findings` accepts — project_id,
    severities, statuses, etc. — without re-declaring that parameter list a
    third time."""
    findings = list_findings(db, visible_department_ids=visible_department_ids, **filters)

    project_pks = {f.project_id for f in findings}
    project_uid_by_pk: dict[int, str] = {}
    if project_pks:
        project_uid_by_pk = dict(
            db.execute(select(Project.id, Project.project_id).where(Project.id.in_(project_pks))).all()
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_EXPORT_COLUMNS)
    for f in findings:
        writer.writerow(
            [
                project_uid_by_pk.get(f.project_id, f.project_id),
                f.check_id,
                f.check_title,
                f.severity.value,
                f.status.value,
                f.status_extended,
                f.service_name,
                f.subservice_name,
                f.region,
                f.resource_type,
                f.resource_name,
                f.resource_uid,
                f.finding_uid,
                f.muted,
                f.mute_reason.value if f.mute_reason else None,
                f.note,
                f.first_seen_at.isoformat(),
                f.updated_at.isoformat(),
            ]
        )
    return buffer.getvalue()


def department_id_for_finding(db: Session, finding_id: int) -> int | None:
    """Looked up before the update so the caller can run the
    department-role check ahead of committing anything — same pattern as
    `services/scans.py::department_id_for_project`. Returns None for a
    finding that doesn't exist; the caller should treat that as a 404, not
    a permission question."""
    return db.execute(
        select(GcpOrganization.department_id)
        .join(Project, Project.gcp_organization_id == GcpOrganization.id)
        .join(Finding, Finding.project_id == Project.id)
        .where(Finding.id == finding_id)
    ).scalar_one_or_none()


def mute_by_check(
    db: Session,
    *,
    project_id: int,
    check_id: str,
    mute_reason: MuteReason,
    note: str | None,
    actor_user_id: int,
) -> int:
    """Mutes every currently-unmuted finding for one check within one
    project in a single action — "mute CMEK for BigQuery," not fifty
    individual clicks. Deliberately skips findings already muted rather
    than overwriting their reason/note: a category mute is a bulk apply to
    the *unmuted* set, never a bulk overwrite of judgements a human already
    made on specific resources. Each finding still gets its own row-level
    write and its own audit entry — this is a loop over `update_finding`'s
    same rule (mute requires a reason), not a second write path — so every
    one of them remains individually unmutable afterwards through the
    existing per-finding endpoint, exactly like any other mute.
    """
    stmt = select(Finding).where(
        Finding.project_id == project_id,
        Finding.check_id == check_id,
        Finding.muted.is_(False),
    )
    findings = list(db.execute(stmt).scalars())
    for finding in findings:
        update_finding(
            db,
            finding_id=finding.id,
            muted=True,
            mute_reason=mute_reason,
            note=note,
            actor_user_id=actor_user_id,
        )
    return len(findings)


def update_finding(
    db: Session,
    *,
    finding_id: int,
    muted: bool,
    mute_reason: MuteReason | None,
    note: str | None,
    actor_user_id: int,
) -> Finding:
    """The only write path for the triage overlay. Status is scan-derived
    and never touched here — there is no parameter for it, so this can
    never be the path that changes it.

    A mute without a reason is indefensible when a customer asks why they
    were told something was fine, so it's rejected here — the DB's own
    CHECK constraint is the backstop, not the primary guard; this raises a
    plain ValueError so the API layer can turn it into a clean 422 instead
    of a raw IntegrityError.
    """
    if muted and mute_reason is None:
        raise ValueError("mute_reason is required when muting a finding")

    finding = db.get(Finding, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)

    before_value = {
        "muted": finding.muted,
        "mute_reason": finding.mute_reason.value if finding.mute_reason else None,
        "note": finding.note,
    }
    finding.muted = muted
    finding.mute_reason = mute_reason
    finding.note = note
    finding.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.flush()

    after_value = {
        "muted": finding.muted,
        "mute_reason": finding.mute_reason.value if finding.mute_reason else None,
        "note": finding.note,
    }
    audit.record(
        db,
        user_id=actor_user_id,
        action_type="finding.update",
        target_type="finding",
        target_id=str(finding.id),
        before_value=before_value,
        after_value=after_value,
    )
    db.commit()
    db.refresh(finding)
    return finding
