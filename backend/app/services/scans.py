"""Single write path for `scans`. Both the API (submission, status reads) and
the worker (state transitions as a scan runs) import this — matching
`services/importer.py`'s role for `findings`, this is the one place a
`scans` row is ever written. The two modules split the terminal states
between them: this file owns queued/running/importing/failed/timeout — the
container-level lifecycle — and importer.py owns succeeded/schema_mismatch/
import_failed — whether the output it produced actually parsed.
"""

from __future__ import annotations

import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.gcp_organization import GcpOrganization
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services import audit
from app.services.rbac import ALL_DEPARTMENTS, is_department_visible
from app.services.errors import ConflictError, InvalidRequestError, NotFoundError


class ProjectNotOnboardedError(InvalidRequestError):
    def __init__(self, project_id: int):
        super().__init__(
            f"project {project_id} is not onboarded for scanning — register it "
            "under Projects (and confirm it hasn't been deleted) before submitting a scan"
        )
        self.project_id = project_id


class ScanNotFoundError(NotFoundError):
    def __init__(self, scan_id: int):
        super().__init__(f"no scan with id {scan_id}")
        self.scan_id = scan_id


class ProjectMissingError(NotFoundError):
    """A `scans` row points at a `projects` row that is not there. Projects are
    soft-deleted, so this should be unreachable — it exists so the worker can
    name the inconsistency in the scan's `error_message` rather than fail on an
    attribute of None."""

    def __init__(self, project_id: int):
        super().__init__(f"scan references project {project_id}, which no longer exists")
        self.project_id = project_id


class ScanNotCancellableError(ConflictError):
    def __init__(self, scan_id: int, status: ScanStatus):
        super().__init__(f"scan {scan_id} is already {status.value} — nothing to cancel")
        self.scan_id = scan_id
        self.status = status


# The states a scan can still be cancelled out of. Every other status is
# already terminal — cancelling it would just be relabelling history.
ACTIVE_STATUSES = frozenset({ScanStatus.queued, ScanStatus.running, ScanStatus.importing})


def department_id_for_project(db: Session, project_id: int) -> int | None:
    """Looked up before submission so the caller can run the department-role
    check ahead of committing anything. Returns None for a project that
    doesn't exist — the caller should treat that as "not onboarded", not as a
    permission question."""
    row = db.execute(
        select(GcpOrganization.department_id)
        .join(Project, Project.gcp_organization_id == GcpOrganization.id)
        .where(Project.id == project_id)
    ).scalar_one_or_none()
    return row


def submit_scan(db: Session, *, project_id: int, actor_user_id: int) -> Scan:
    project = db.get(Project, project_id)
    if project is None or project.deleted:
        raise ProjectNotOnboardedError(project_id)

    scan = Scan(
        project_id=project.id,
        status=ScanStatus.queued,
        sa_impersonated=project.target_sa_email,
        triggered_by_user_id=actor_user_id,
    )
    db.add(scan)
    db.flush()

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="scan.submit",
        target_type="scan",
        target_id=str(scan.id),
        before_value=None,
        after_value={"project_id": project.id, "status": scan.status.value},
    )
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, *, scan_id: int, visible_department_ids: set[int] | str) -> Scan:
    """Scoped by-id read. See `services/findings.py::get_finding` for the full
    note on why this parameter is required rather than optional, and why an
    out-of-scope row is a 404 rather than a 403 — this was the precedent that
    note refers to, and it had the same hole.

    Internal callers with no user behind them (`services/compliance.py`, the
    Celery worker) pass `ALL_DEPARTMENTS` explicitly.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    if not is_department_visible(department_id_for_project(db, scan.project_id), visible_department_ids):
        raise ScanNotFoundError(scan_id)
    return scan


def list_scans(db: Session, *, visible_department_ids: set[int] | str) -> list[Scan]:
    stmt = (
        select(Scan)
        .join(Project, Project.id == Scan.project_id)
        .join(GcpOrganization, GcpOrganization.id == Project.gcp_organization_id)
    )
    if visible_department_ids != ALL_DEPARTMENTS:
        stmt = stmt.where(GcpOrganization.department_id.in_(visible_department_ids))
    stmt = stmt.order_by(Scan.triggered_at.desc())
    return list(db.execute(stmt).scalars())


def is_stale(scan: Scan, *, timeout_seconds: int) -> bool:
    """A scan reported as still `running` well past its own ceiling — almost
    always because the worker process that owned it died before it could
    finalize the row. Computed at read time; nothing writes this back, so
    there is no scheduler to keep alive (matching the "no scheduler
    container" constraint)."""
    if scan.status != ScanStatus.running or scan.started_at is None:
        return False
    started_at = scan.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=datetime.timezone.utc)
    age = datetime.datetime.now(datetime.timezone.utc) - started_at
    return age.total_seconds() > timeout_seconds


# ── operator action ──────────────────────────────────────────────────────


def cancel_scan(db: Session, *, scan_id: int, actor_user_id: int) -> Scan:
    """Marks a wedged or unwanted scan cancelled immediately — this is the
    authoritative status write, made synchronously from the API request so
    the UI reflects it without waiting on the worker. Killing the actual
    sibling container (if one is still running) is a separate, best-effort
    step (see `worker.tasks.cleanup_cancelled_scan`) because the API process
    deliberately has no Docker socket access — only the worker does."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    if scan.status not in ACTIVE_STATUSES:
        raise ScanNotCancellableError(scan_id, scan.status)

    before = {"status": scan.status.value}
    scan.status = ScanStatus.cancelled
    scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
    scan.error_message = "Cancelled from the UI."

    audit.record(
        db,
        user_id=actor_user_id,
        action_type="scan.cancel",
        target_type="scan",
        target_id=str(scan.id),
        before_value=before,
        after_value={"status": scan.status.value},
    )
    db.commit()
    db.refresh(scan)
    return scan


# ── worker-side state transitions ───────────────────────────────────────────


def mark_running(db: Session, *, scan_id: int, container_id: str, reports_path: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    if scan.status == ScanStatus.cancelled:
        return scan
    scan.status = ScanStatus.running
    scan.started_at = datetime.datetime.now(datetime.timezone.utc)
    scan.container_id = container_id
    scan.reports_path = reports_path
    db.commit()
    db.refresh(scan)
    return scan


def finalize_scan_failure(
    db: Session,
    *,
    scan_id: int,
    exit_code: int | None,
    timed_out: bool,
    error_message: str,
) -> Scan:
    """Terminal transition for a run that produced no usable output — the
    container itself errored, or was killed for exceeding the time ceiling.
    Never called for a successful exit; that path is `mark_importing` below,
    which hands off to `services/importer.py::import_scan_results` — the
    only place a scan can reach `succeeded` from here on."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    if scan.status == ScanStatus.cancelled:
        # An operator cancelled this scan while the container was still
        # running — the cancel already wrote the terminal state and its own
        # completed_at. The still-in-flight task reaching this point (its
        # `docker wait` having just been unblocked by the cancel's own
        # cleanup kill) must not clobber that with "failed"/"timeout".
        return scan

    scan.exit_code = exit_code
    scan.error_message = error_message
    scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
    scan.status = ScanStatus.timeout if timed_out else ScanStatus.failed

    db.commit()
    db.refresh(scan)
    return scan


def mark_importing(db: Session, *, scan_id: int, exit_code: int) -> Scan:
    """The scan container exited successfully — `completed_at` is set here
    because the actual scanning work (the multi-minute part) is done at this
    point, independent of how long parsing takes. Everything from here is
    `services/importer.py`'s to decide: succeeded, schema_mismatch, or
    import_failed."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)
    if scan.status == ScanStatus.cancelled:
        return scan

    scan.exit_code = exit_code
    scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
    scan.status = ScanStatus.importing

    db.commit()
    db.refresh(scan)
    return scan
