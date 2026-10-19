import os

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user
from app.config import Settings, get_settings
from app.db import get_db
from app.models.user_department_role import Role
from app.schemas.scan import ScanCreateRequest, ScanLogResponse, ScanResponse
from app.services.rbac import require_department_role, visible_department_ids
from app.services.scans import (
    cancel_scan,
    department_id_for_project,
    get_scan,
    is_stale,
    list_scans,
    ProjectNotOnboardedError,
    submit_scan,
)
from app.worker.tasks import cleanup_cancelled_scan, run_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])
_MAX_LOG_CHARS = 100_000


def _to_response(scan, *, settings: Settings) -> ScanResponse:
    stale = is_stale(scan, timeout_seconds=int(settings["SCAN_TIMEOUT_SECONDS"]))
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        status=scan.status.value,
        triggered_by_user_id=scan.triggered_by_user_id,
        triggered_at=scan.triggered_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        pass_count=scan.pass_count,
        fail_count=scan.fail_count,
        exit_code=scan.exit_code,
        error_message=scan.error_message,
        stale=stale,
        compliance_drift_detected=scan.compliance_drift_detected,
    )


@router.get("", response_model=list[ScanResponse])
def list_scans_endpoint(
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    visible = visible_department_ids(db, current)
    return [_to_response(scan, settings=settings) for scan in list_scans(db, visible_department_ids=visible)]


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def submit_scan_endpoint(
    body: ScanCreateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    department_id = department_id_for_project(db, body.project_id)
    if department_id is None:
        raise ProjectNotOnboardedError(body.project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    scan = submit_scan(db, project_id=body.project_id, actor_user_id=current.user.id)

    # Enqueued after the row and its audit entry are committed, so a scan id
    # the task references always exists — nothing here can race the insert.
    run_scan_task.delay(scan.id)
    return _to_response(scan, settings=settings)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    scan = get_scan(db, scan_id=scan_id, visible_department_ids=visible_department_ids(db, current))
    department_id = department_id_for_project(db, scan.project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    scan = cancel_scan(db, scan_id=scan_id, actor_user_id=current.user.id)

    # Fire-and-forget: kills the sibling container if one is still running,
    # or is a no-op if it already exited (the orphaned case this button
    # exists for). The status write above already happened either way.
    cleanup_cancelled_scan.delay(scan.id, scan.container_id)
    return _to_response(scan, settings=settings)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    scan = get_scan(db, scan_id=scan_id, visible_department_ids=visible_department_ids(db, current))
    return _to_response(scan, settings=settings)


@router.get("/{scan_id}/log", response_model=ScanLogResponse)
def get_scan_log_endpoint(
    scan_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    scan = get_scan(db, scan_id=scan_id, visible_department_ids=visible_department_ids(db, current))
    require_department_role(
        db,
        current,
        department_id=department_id_for_project(db, scan.project_id),
        minimum=Role.editor,
    )

    if not scan.reports_path:
        return ScanLogResponse(scan_id=scan_id, log="")

    log_path = os.path.join(scan.reports_path, "prowler.log")
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            log_text = f.read(_MAX_LOG_CHARS + 1)
    except FileNotFoundError:
        log_text = ""
    if len(log_text) > _MAX_LOG_CHARS:
        log_text = log_text[:_MAX_LOG_CHARS] + "\n[log truncated]"
    return ScanLogResponse(scan_id=scan_id, log=log_text)
