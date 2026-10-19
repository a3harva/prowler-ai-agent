from fastapi import APIRouter, Depends, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_current_user
from app.db import get_db
from app.models.report import ReportMode
from app.models.user_department_role import Role
from app.schemas.report import (
    ReportContentResponse,
    ReportCreateRequest,
    ReportResponse,
    ReportUpdateContentRequest,
)
from app.services.errors import ReportPdfNotAvailableError
from app.services.rbac import require_department_role, visible_department_ids
from app.services.reports import get_report, list_reports, submit_report, update_report_content
from app.services.scans import department_id_for_project
from app.worker.tasks import generate_deep_report_task, generate_report_task

router = APIRouter(prefix="/api/reports", tags=["reports"])

# No try/except anywhere in this file. Service errors carry their own status
# (services/errors.py) and api/main.py translates them in one handler.


@router.get("", response_model=list[ReportResponse])
def list_reports_endpoint(
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Open to any signed-in user, scoped server-side — same rule as the
    scans, findings and organizations listings. Deliberately returns
    ReportResponse, not ReportContentResponse: a page listing twenty reports
    should not ship twenty full documents to render a status column."""
    return list_reports(db, visible_department_ids=visible_department_ids(db, current))


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def submit_report_endpoint(
    body: ReportCreateRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Editor or above — generating a customer-facing document is a
    comparable-weight action to triggering a scan, not a read."""
    department_id = department_id_for_project(db, body.project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)

    mode = ReportMode(body.mode)
    report = submit_report(
        db,
        project_id=body.project_id,
        actor_user_id=current.user.id,
        include_muted=body.include_muted,
        mode=mode,
        instructions=body.instructions,
    )

    # Enqueued only after the row and its audit entry are committed, so the id
    # the task reads always exists — same ordering as scan submission. Both
    # tasks are on the `reports` queue (celery_app routes `reports.*`), so a
    # deep report still never queues behind a scan.
    if mode is ReportMode.deep:
        generate_deep_report_task.delay(report.id)
    else:
        generate_report_task.delay(report.id)
    return report


@router.get("/{report_id}", response_model=ReportContentResponse)
def get_report_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    return get_report(db, report_id=report_id, visible_department_ids=visible)


@router.patch("/{report_id}", response_model=ReportContentResponse)
def update_report_content_endpoint(
    report_id: int,
    body: ReportUpdateContentRequest,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Editor or above — correcting a customer-facing document is the same
    weight as generating it, not a read. `report.project_id` always resolves
    to a real department (a report cannot exist without one), so this gate is
    unconditional rather than the fail-open shape flagged in findings.py."""
    visible = visible_department_ids(db, current)
    report = get_report(db, report_id=report_id, visible_department_ids=visible)
    department_id = department_id_for_project(db, report.project_id)
    require_department_role(db, current, department_id=department_id, minimum=Role.editor)
    return update_report_content(
        db, report_id=report_id, content=body.content, actor_user_id=current.user.id
    )


@router.get("/{report_id}/download")
def download_report_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    report = get_report(db, report_id=report_id, visible_department_ids=visible)
    return Response(
        content=report.content or "",
        media_type="text/markdown",
        headers={
            "Content-Disposition":
                f'attachment; filename="{report.task_reference_id}.md"'
        },
    )


@router.get("/{report_id}/download.pdf")
def download_report_pdf_endpoint(
    report_id: int,
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    visible = visible_department_ids(db, current)
    report = get_report(db, report_id=report_id, visible_department_ids=visible)
    if report.pdf_content is None:
        raise ReportPdfNotAvailableError(report_id)
    return Response(
        content=report.pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="{report.task_reference_id}.pdf"'
        },
    )
