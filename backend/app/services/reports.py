"""Single write path for `reports`, plus the deterministic half of report
generation.

The split that matters here: **everything except the prose is built in this
module**, from the database, with no model involved. Gemini writes the pillar
narratives and the per-check "what this means" paragraphs and nothing else.
Every `gcloud` command a customer reads comes verbatim from Prowler's own
version-pinned output, carried through `services/importer.py` into the
`findings` row. A model that invents a remediation command is the single worst
failure this feature could have, so it is never given the chance.

`build_report_payload` and `render_markdown` are both pure with respect to
Vertex — they are exercised in tests against a seeded database without a
network or a credential.
"""

from __future__ import annotations

import datetime
import secrets
from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingStatus, Severity
from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.report import Report, ReportMode, ReportStatus
from app.models.scan import Scan, ScanStatus
from app.models.waf_pillar_mapping import SECURITY_PILLAR, WAF_PILLARS, WafPillarMapping
from app.services import audit
from app.services.errors import InvalidRequestError, NotFoundError
from app.services.rbac import ALL_DEPARTMENTS, is_department_visible

# Statuses that belong in a remediation report. PASS is excluded because there
# is nothing to remediate; RESOURCE_DOES_NOT_EXIST because a resource that is
# gone cannot attest to anything — the same treatment `services/compliance.py`
# already gives it.
REPORTABLE_STATUSES = (FindingStatus.FAIL, FindingStatus.MANUAL)

# Most-severe first, matching the findings screen's default ordering.
_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


class ReportNotFoundError(NotFoundError):
    def __init__(self, report_id: int):
        super().__init__(f"no report with id {report_id}")
        self.report_id = report_id


class NoScanToReportOnError(InvalidRequestError):
    def __init__(self, project_id: int):
        super().__init__(
            f"project {project_id} has no succeeded scan to report on — run a scan first"
        )
        self.project_id = project_id


class NoReportableFindingsError(InvalidRequestError):
    """Nothing is left to report on.

    Caught at submit time rather than in the worker, so the user gets an
    actionable answer immediately instead of a failed row.

    The two causes need different answers, which is why the message branches:
    a scan predating remediation-detail capture is fixed by re-scanning, while a
    project whose findings are all muted is fixed by including them — and
    telling someone to re-scan when the real problem is that they muted
    everything sends them somewhere useless.
    """

    def __init__(self, project_id: int, *, all_muted: bool = False):
        if all_muted:
            super().__init__(
                f"every reportable finding on project {project_id} is muted — turn on "
                "'include muted findings' to report on them"
            )
        else:
            super().__init__(
                f"project {project_id} has no findings carrying remediation detail — its "
                "latest scan predates remediation-detail capture, so run a new scan first"
            )
        self.project_id = project_id
        self.all_muted = all_muted


def pillar_for(categories: str | None, mapping: dict[str, str]) -> tuple[str, bool]:
    """Returns `(pillar, was_unknown)`.

    Prowler sometimes pipe-separates two tags ("secrets | identity-access").
    First-listed wins: simple, deterministic, auditable. In the reference scan
    this only changes the outcome for `logging`-led pairs, which route to
    Operational Excellence; every other combination lands on the same pillar
    whichever tag is read.

    An empty or unrecognised tag falls back to Security rather than vanishing —
    5.6% of the reference scan has no category at all, and a report that
    silently drops one finding in twenty is worse than one that over-assigns.
    """
    first = (categories or "").split("|")[0].strip()
    if first in mapping:
        return mapping[first], False
    return SECURITY_PILLAR, bool(first)


def _load_pillar_mapping(db: Session) -> dict[str, str]:
    return {row.category: row.pillar for row in db.execute(select(WafPillarMapping)).scalars()}


def latest_succeeded_scan(db: Session, *, project_id: int) -> Scan | None:
    return db.execute(
        select(Scan)
        .where(Scan.project_id == project_id, Scan.status == ScanStatus.succeeded)
        .order_by(Scan.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def build_report_payload(
    db: Session, *, project_id: int, include_muted: bool = False
) -> dict[str, Any]:
    """Groups the project's reportable findings by pillar, then by check.

    One section per check, not per resource: a check that fails on forty
    buckets needs one explanation and one remediation block, with the forty
    resources in a table underneath. That is what keeps a report readable at
    fifty checks instead of two hundred rows of repeated prose.

    Findings with no `description` are skipped and counted — they were imported
    before remediation-detail capture, so there is nothing to explain and no
    remediation to print. Counting them keeps the omission visible in the
    report rather than a silent discrepancy against the findings screen.

    Muted findings are excluded unless `include_muted`. A mute is a recorded
    decision not to remediate, so by default it does not belong in a
    remediation report. The excluded count is returned so the document can say
    so rather than quietly presenting an incomplete picture.
    """
    mapping = _load_pillar_mapping(db)

    conditions = [
        Finding.project_id == project_id,
        Finding.status.in_(REPORTABLE_STATUSES),
    ]

    # Muted findings are excluded at the query itself, not loaded and then
    # discarded. The count still needs its own query, since the excluded rows
    # are no longer read.
    muted_excluded = 0
    if not include_muted:
        muted_excluded = db.execute(
            select(func.count()).select_from(Finding).where(*conditions, Finding.muted.is_(True))
        ).scalar_one()
        conditions.append(Finding.muted.is_(False))

    findings = list(db.execute(select(Finding).where(*conditions)).scalars())

    pillars: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    skipped = 0
    unknown_categories = 0

    for finding in findings:
        if not (finding.description or "").strip():
            skipped += 1
            continue
        pillar, was_unknown = pillar_for(finding.categories, mapping)
        if was_unknown:
            unknown_categories += 1

        group = pillars[pillar].setdefault(
            finding.check_id,
            {
                "check_id": finding.check_id,
                "check_title": finding.check_title,
                "severity": finding.severity.value,
                # One check belongs to exactly one Prowler service, so this is
                # a property of the group rather than of a resource. Carried
                # on the group so the deep report's cross-check analysis can
                # say "three services" without re-querying — see
                # `agents/report_ledger.py::build_index`.
                "service_name": finding.service_name,
                "categories": finding.categories or "",
                "description": finding.description,
                "risk": finding.risk,
                "remediation_text": finding.remediation_text,
                "remediation_cli": finding.remediation_cli,
                "remediation_terraform": finding.remediation_terraform,
                "resources": [],
            },
        )
        group["resources"].append(
            {
                "resource_name": finding.resource_name,
                "region": finding.region,
                "status_extended": finding.status_extended or "",
                "muted": finding.muted,
                "mute_reason": finding.mute_reason.value if finding.mute_reason else None,
            }
        )

    ordered = {}
    for pillar in WAF_PILLARS:
        groups = pillars.get(pillar)
        if not groups:
            # Empty pillars are omitted entirely — no filler, no "not
            # applicable" placeholder. Prowler is a security scanner, so Cost,
            # Performance and Sustainability are reliably empty.
            continue
        ordered[pillar] = sorted(
            groups.values(),
            key=lambda g: (_SEVERITY_RANK[Severity(g["severity"])], g["check_id"]),
        )

    return {
        "pillars": ordered,
        "skipped_finding_count": skipped,
        "unknown_category_count": unknown_categories,
        "muted_excluded_count": muted_excluded,
        "severity_counts": {
            pillar: Counter(g["severity"] for g in groups) for pillar, groups in ordered.items()
        },
    }


def build_check_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`check_id` -> the facts about that check, flattened out of the payload.

    One entry per check group, which is also one `###` section in the finished
    document. Both the renderer (for the per-wave and per-theme arithmetic it
    emits) and the deep report's gates (`agents/report_ledger.py`) walk this,
    and they must walk the *same* index or the numbers in the document and the
    numbers the gates check would be computed twice from two definitions.

    A `check_id` can only appear under one pillar — grouping is by pillar
    first and `pillar_for` is a pure function of the finding's category — so a
    flat index loses nothing and makes every lookup O(1) rather than a scan
    across six pillars.
    """
    index: dict[str, dict[str, Any]] = {}
    for pillar, groups in payload["pillars"].items():
        for group in groups:
            index[group["check_id"]] = {
                "pillar": pillar,
                "check_title": group["check_title"],
                "severity": group["severity"],
                "categories": group.get("categories") or "",
                # Absent on a payload built before `service_name` was carried
                # on the group. Empty rather than raising, so an older payload
                # still renders and still verifies.
                "service_name": group.get("service_name") or "",
                "resource_count": len(group["resources"]),
            }
    return index


# ── write path ───────────────────────────────────────────────────────────────


# A guidance field, not a document. Long enough for a paragraph or two of
# real steer, short enough that it cannot become the prompt.
MAX_INSTRUCTIONS_CHARS = 4000


class InstructionsTooLongError(InvalidRequestError):
    def __init__(self, length: int):
        super().__init__(
            f"instructions are {length} characters; the limit is {MAX_INSTRUCTIONS_CHARS}. "
            "This field steers emphasis and tone — it is not the report brief."
        )


def submit_report(
    db: Session,
    *,
    project_id: int,
    actor_user_id: int,
    include_muted: bool = False,
    mode: ReportMode = ReportMode.standard,
    instructions: str | None = None,
) -> Report:
    """Refuses up front rather than queueing a job that cannot succeed: no
    succeeded scan, or no finding carrying remediation detail. Both are
    knowable at submit time, and both have an actionable answer ("run a scan")
    that a user should not have to wait for a failed row to discover."""
    instructions = (instructions or "").strip() or None
    if instructions and len(instructions) > MAX_INSTRUCTIONS_CHARS:
        raise InstructionsTooLongError(len(instructions))

    project = db.get(Project, project_id)
    if project is None or project.deleted:
        raise NotFoundError(f"no project with id {project_id}")

    scan = latest_succeeded_scan(db, project_id=project_id)
    if scan is None:
        raise NoScanToReportOnError(project_id)

    # One aggregate query answers both questions the guard needs — whether
    # anything is reportable in the requested scope, and (only if not) whether
    # everything reportable is muted — instead of a second existence query
    # asking the same question again on the failure path.
    #
    # `func.trim(...) != ""` matches `build_report_payload`'s own `.strip()`
    # skip check exactly. A plain `!= ""` here previously let a whitespace-only
    # description count as reportable at submit time while the payload build
    # would still skip it, which could pass this guard and then produce an
    # empty document anyway.
    has_unmuted, has_muted = db.execute(
        select(
            func.bool_or(Finding.muted.is_(False)),
            func.bool_or(Finding.muted.is_(True)),
        ).where(
            Finding.project_id == project_id,
            Finding.status.in_(REPORTABLE_STATUSES),
            Finding.description.isnot(None),
            func.trim(Finding.description) != "",
        )
    ).one()
    has_unmuted, has_muted = bool(has_unmuted), bool(has_muted)

    # The guard has to use the SAME scope the report will. Without that, a
    # project whose reportable findings are all muted passes submission and then
    # produces an empty document — exactly what this guard exists to prevent.
    has_reportable = has_unmuted or (include_muted and has_muted)
    if not has_reportable:
        # Distinguish "nothing at all" from "nothing once muting is applied", so
        # the error can point at the fix that would actually work.
        all_muted = not include_muted and has_muted
        raise NoReportableFindingsError(project_id, all_muted=all_muted)

    task_reference_id = f"RPT-{secrets.token_hex(3)}"
    report = Report(
        project_id=project_id,
        scan_id=scan.id,
        task_reference_id=task_reference_id,
        status=ReportStatus.queued,
        requested_by_user_id=actor_user_id,
        include_muted=include_muted,
        mode=mode,
        instructions=instructions,
        # The LangGraph thread this run will live on. Equal to the reference
        # id rather than derived from it, so a human quoting "RPT-a1b2c3" in a
        # support conversation names the exact thread an engineer can resume.
        # Set for both modes; only the deep path reads it.
        graph_thread_id=task_reference_id,
    )
    db.add(report)
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="report.request",
        target_type="report",
        target_id=str(report.id),
        before_value=None,
        after_value={"project_id": project_id, "scan_id": scan.id,
                     "task_reference_id": report.task_reference_id,
                     "include_muted": include_muted, "mode": mode.value,
                     "has_instructions": instructions is not None},
    )
    db.commit()
    db.refresh(report)
    return report


def get_report(
    db: Session, *, report_id: int, visible_department_ids: set[int] | str
) -> Report:
    """Scoped by-id read. See `services/findings.py::get_finding` for the full
    note on why the parameter is required and why an out-of-scope row answers
    404 rather than 403.

    The stakes are highest here of the three: a report body is a finished,
    customer-facing assessment of another department's estate, not a single
    row. Internal callers with no user behind them — the Celery worker, and
    this module's own state transitions below — pass `ALL_DEPARTMENTS`
    explicitly.
    """
    report = db.get(Report, report_id)
    if report is None:
        raise ReportNotFoundError(report_id)
    department_id = db.execute(
        select(GcpOrganization.department_id)
        .join(Project, Project.gcp_organization_id == GcpOrganization.id)
        .where(Project.id == report.project_id)
    ).scalar_one_or_none()
    if not is_department_visible(department_id, visible_department_ids):
        raise ReportNotFoundError(report_id)
    return report


def list_reports(db: Session, *, visible_department_ids: set[int] | str) -> list[Report]:
    """Scoped exactly like `services/findings.py::list_findings` — through the
    project's organization to its department."""
    stmt = (
        select(Report)
        .join(Project, Project.id == Report.project_id)
        .join(GcpOrganization, GcpOrganization.id == Project.gcp_organization_id)
    )
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(GcpOrganization.department_id.in_(visible_department_ids))
    return list(db.execute(stmt.order_by(Report.id.desc())).scalars())


def mark_generating(db: Session, *, report_id: int) -> Report:
    report = get_report(db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS)
    report.status = ReportStatus.generating
    db.commit()
    db.refresh(report)
    return report


def finalize_report(
    db: Session,
    *,
    report_id: int,
    content: str,
    pdf_content: bytes,
    skipped: int,
    unknown_categories: int,
    format_warnings: str | None = None,
    analysis: dict | None = None,
    verification: dict | None = None,
    critique: dict | None = None,
    live_context: dict | None = None,
) -> Report:
    """`pdf_content` is required, not optional — matching this module's own
    all-or-nothing principle for `content` above. A WeasyPrint failure fails
    report generation entirely rather than storing Markdown with no PDF."""
    report = get_report(db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS)
    report.content = content
    report.pdf_content = pdf_content
    report.format_warnings = format_warnings
    # Deep-mode only; left untouched (and so null) for a standard report
    # rather than written as empty dicts, so "was this produced by the agent"
    # is answerable from the row.
    if analysis is not None:
        report.analysis = analysis
    if verification is not None:
        report.verification = verification
    if critique is not None:
        report.critique = critique
    if live_context is not None:
        report.live_context = live_context
    report.skipped_finding_count = skipped
    report.unknown_category_count = unknown_categories
    report.status = ReportStatus.completed
    report.completed_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(report)
    return report


def fail_report(db: Session, *, report_id: int, error_message: str) -> Report:
    """Stores no content. All-or-nothing, matching the import pipeline: a
    partially written customer-facing document is worse than a clear failure
    the user can retry."""
    report = get_report(db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS)
    report.status = ReportStatus.failed
    report.error_message = error_message
    report.content = None
    report.completed_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(report)
    return report


def update_report_content(
    db: Session, *, report_id: int, content: str, actor_user_id: int
) -> Report:
    """A human correction after generation — not a re-run of the pipeline.
    The ledger gates (C1-C6) ran once at generation time against the original
    document and are not re-checked here; this is a deliberate, audited
    override for fixing prose after the fact, same posture as any other
    human-authored correction to a customer-facing document.

    Clears `pdf_content`: it was built by WeasyPrint from the *original*
    Markdown, and `content` is no longer that document, so the stored PDF
    would silently drift out of sync with what a reader sees on screen. The
    "Download PDF" button already hides itself once `has_pdf` is false; the
    browser Print Preview path is how an edited report gets printed.
    """
    report = get_report(db, report_id=report_id, visible_department_ids=ALL_DEPARTMENTS)
    if report.status != ReportStatus.completed:
        raise InvalidRequestError("only a completed report can be edited")

    before_length = len(report.content or "")
    report.content = content
    report.pdf_content = None
    report.content_edited_at = datetime.datetime.now(datetime.timezone.utc)

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="report.edit_content",
        target_type="report",
        target_id=str(report.id),
        before_value={"content_length": before_length},
        after_value={"content_length": len(content)},
    )
    db.commit()
    db.refresh(report)
    return report
