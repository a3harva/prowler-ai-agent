from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreateRequest(BaseModel):
    org_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    department_id: int


class OrganizationUpdateRequest(BaseModel):
    # No org_id field — the GCP identifier is immutable once registered, so
    # there's structurally nothing here to change it with.
    name: str = Field(min_length=1)
    department_id: int


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    org_id: str
    name: str
    department_id: int
    deleted: bool
