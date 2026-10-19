from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.db import get_db
from app.schemas.compliance import (
    ComplianceFrameworkOption,
    ComplianceReportResponse,
    ComplianceSeedRequest,
    ComplianceSeedResponse,
)
from app.services.compliance import (
    compliance_report,
    list_frameworks,
    seed_rulebook_from_scan,
)
from app.services.rbac import ALL_DEPARTMENTS, visible_department_ids
from app.services.scans import department_id_for_project

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _require_visible_project(db: Session, current: CurrentUser, project_id: int) -> None:
    """Same existence-hiding scoping the list endpoints apply by filtering
    — a project outside the caller's visible departments 404s rather than
    403s, so a report page never leaks that a project exists (or its score)
    to someone with no grant on it at all."""
    department_id = department_id_for_project(db, project_id)
    visible = visible_department_ids(db, current)
    if department_id is None or (visible != ALL_DEPARTMENTS and department_id not in visible):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no project with id {project_id}")


@router.post("/seed", response_model=ComplianceSeedResponse)
def seed_rulebook_endpoint(
    body: ComplianceSeedRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(require_admin),
):
    summary = seed_rulebook_from_scan(db, scan_id=body.scan_id, actor_user_id=current.user.id)
    return ComplianceSeedResponse(**summary)


@router.get("/frameworks", response_model=list[ComplianceFrameworkOption])
def list_frameworks_endpoint(
    project_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    _require_visible_project(db, current, project_id)
    return [ComplianceFrameworkOption(**row) for row in list_frameworks(db, project_id=project_id)]


@router.get("/report", response_model=ComplianceReportResponse)
def compliance_report_endpoint(
    project_id: int,
    framework: str,
    framework_name: str,
    include_muted: bool = False,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    _require_visible_project(db, current, project_id)
    report = compliance_report(
        db, project_id=project_id, framework=framework, framework_name=framework_name,
        include_muted=include_muted,
    )
    return ComplianceReportResponse(**report)
