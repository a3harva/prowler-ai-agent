import datetime

from pydantic import BaseModel, ConfigDict


class ScanCreateRequest(BaseModel):
    # References projects.id (the internal FK), not the GCP project string.
    project_id: int


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    triggered_by_user_id: int
    triggered_at: datetime.datetime
    started_at: datetime.datetime | None
    completed_at: datetime.datetime | None
    pass_count: int | None
    fail_count: int | None
    exit_code: int | None
    error_message: str | None
    # Computed at read time rather than written by a scheduler — a scan still
    # shown as "running" long past SCAN_TIMEOUT_SECONDS (e.g. because the
    # worker that owned it crashed before it could finalize) is flagged here
    # without any background process.
    stale: bool
    # Set by the importer when the scan's own inline COMPLIANCE
    # mappings didn't match the loaded rulebook — the real trigger is a
    # Prowler upgrade nobody re-seeded the rulebook for.
    compliance_drift_detected: bool


class ScanLogResponse(BaseModel):
    scan_id: int
    log: str
