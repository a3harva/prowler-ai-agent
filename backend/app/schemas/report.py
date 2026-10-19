import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.services.reports import MAX_INSTRUCTIONS_CHARS


class ReportCreateRequest(BaseModel):
    # References projects.id (the internal FK), not the GCP project string —
    # same convention as ScanCreateRequest.
    project_id: int
    # Defaults to False: a mute records a decision not to remediate, so muted
    # findings are out of scope for a remediation report unless asked for.
    include_muted: bool = False
    # Defaults to standard so an existing client keeps its existing behaviour.
    mode: Literal["standard", "deep"] = "standard"
    # Steers emphasis and tone in deep mode. Capped here as well as in the
    # service: the service cap is the one that holds (it is the only write
    # path), this one turns an over-long field into a 422 with a field name
    # rather than a generic error.
    instructions: str | None = Field(default=None, max_length=MAX_INSTRUCTIONS_CHARS)


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    scan_id: int
    task_reference_id: str
    status: str
    mode: str
    requested_by_user_id: int
    include_muted: bool
    has_pdf: bool
    error_message: str | None
    format_warnings: str | None
    skipped_finding_count: int
    unknown_category_count: int
    created_at: datetime.datetime
    completed_at: datetime.datetime | None
    content_edited_at: datetime.datetime | None


class ReportUpdateContentRequest(BaseModel):
    content: str = Field(min_length=1)


class ReportContentResponse(ReportResponse):
    """The list endpoint deliberately omits `content` — a page showing twenty
    reports should not ship twenty full documents to render a status column.

    `verification` and `critique` ride along with the content because they are
    about *this document*: which gates ran on it, and what the reviewing pass
    thought. `analysis` is deliberately NOT exposed — it is the raw artifact
    bundle kept for reproducibility, it can be large, and everything in it
    that a reader should see is already in the rendered document.
    """

    content: str | None
    instructions: str | None
    verification: dict[str, Any] | None
    critique: dict[str, Any] | None
