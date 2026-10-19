import datetime

from pydantic import BaseModel, ConfigDict


class DepartmentCreateRequest(BaseModel):
    freshservice_id: str


class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    freshservice_id: str
    name: str
    domains: list[str]
    deleted: bool
    created_at: datetime.datetime
