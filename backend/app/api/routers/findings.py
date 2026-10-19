from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user
from app.db import get_db
from app.models.finding import FindingStatus, MuteReason, Severity
from app.models.user_department_role import Role
from app.schemas.finding import (
    FindingBulkMuteResponse,
    FindingMuteByCheckRequest,
    FindingResponse,
    FindingUpdateRequest,
)
from app.services.findings import (
    department_id_for_finding,
    export_findings_csv,
    get_finding,
    list_findings,
    mute_by_check,
    update_finding,
)
from app.services.rbac import require_department_role, visible_department_ids
from app.services.scans import department_id_for_project

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _finding_filters(
    project_id: int | None = None,
    severity: list[Severity] = Query(default=[]),
    status: list[FindingStatus] = Query(default=[]),
    muted: list[bool] = Query(default=[]),
    mute_reason: list[MuteReason] = Query(default=[]),
    service_name: list[str] = Query(default=[]),
    subservice_name: list[str] = Query(default=[]),
    region: list[str] = Query(default=[]),
    resource_type: list[str] = Query(default=[]),
    check_id: list[str] = Query(default=[]),
    search: str | None = None,
) -> dict:
    """The one place query params for both `GET /findings` and
    `GET /findings/export` are parsed — sharing this dependency is what
    keeps the two endpoints from drifting apart on what a filter means."""
    return dict(
        project_id=project_id,
        severities=severity,
        statuses=status,
        muted=muted,
        mute_reasons=mute_reason,
        service_names=service_name,
        subservice_names=subservice_name,
        regions=region,
        resource_types=resource_type,
        check_ids=check_id,
        search=search,
    )


@router.get("", response_model=list[FindingResponse])
def list_findings_endpoint(
    filters: dict = Depends(_finding_filters),
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    return list_findings(db, visible_department_ids=visible, **filters)


@router.get("/export")
def export_findings_endpoint(
    filters: dict = Depends(_finding_filters),
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    csv_text = export_findings_csv(db, visible_department_ids=visible, **filters)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="findings.csv"'},
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_endpoint(
    finding_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    return get_finding(db, finding_id=finding_id, visible_department_ids=visible)


@router.post("/mute-by-check", response_model=FindingBulkMuteResponse)
def mute_by_check_endpoint(
    body: FindingMuteByCheckRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    department_id = department_id_for_project(db, body.project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    count = mute_by_check(
        db,
        project_id=body.project_id,
        check_id=body.check_id,
        mute_reason=body.mute_reason,
        note=body.note,
        actor_user_id=current.user.id,
    )
    return FindingBulkMuteResponse(muted_count=count)


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_endpoint(
    finding_id: int,
    body: FindingUpdateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    department_id = department_id_for_finding(db, finding_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    return update_finding(
        db,
        finding_id=finding_id,
        muted=body.muted,
        mute_reason=body.mute_reason,
        note=body.note,
        actor_user_id=current.user.id,
    )
