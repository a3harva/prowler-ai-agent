import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.finding import MuteReason


class FindingUpdateRequest(BaseModel):
    # Status has no field here at all — it's scan-derived and never
    # hand-editable, so there's structurally nothing to change it with.
    muted: bool
    mute_reason: MuteReason | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _mute_requires_a_reason(self) -> "FindingUpdateRequest":
        if self.muted and self.mute_reason is None:
            raise ValueError("mute_reason is required when muting a finding")
        return self


class FindingMuteByCheckRequest(BaseModel):
    project_id: int
    check_id: str
    mute_reason: MuteReason
    note: str | None = None


class FindingBulkMuteResponse(BaseModel):
    muted_count: int


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    check_id: str
    resource_uid: str
    finding_uid: str
    check_title: str
    severity: str
    status: str
    status_extended: str | None
    region: str
    muted: bool
    mute_reason: str | None
    note: str | None
    service_name: str
    subservice_name: str | None
    resource_type: str
    resource_name: str
    last_scan_id: int
    first_seen_at: datetime.datetime
    updated_at: datetime.datetime
