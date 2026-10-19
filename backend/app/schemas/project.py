import datetime

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreateRequest(BaseModel):
    project_id: str = Field(min_length=1)
    gcp_organization_id: int
    target_sa_email: str = Field(min_length=1)


class ProjectUpdateRequest(BaseModel):
    # No project_id field — the GCP identifier is immutable once
    # registered, so there's structurally nothing here to change it with.
    gcp_organization_id: int
    target_sa_email: str = Field(min_length=1)


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: str
    gcp_organization_id: int
    target_sa_email: str
    deleted: bool
    created_at: datetime.datetime
