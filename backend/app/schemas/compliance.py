from typing import Literal

from pydantic import BaseModel

ComplianceRequirementStatus = Literal["pass", "fail", "needs_review", "not_assessed"]


class ComplianceSeedRequest(BaseModel):
    scan_id: int


class ComplianceSeedResponse(BaseModel):
    framework_count: int
    requirement_count: int
    prowler_version: str
    frameworks: list[str]


class ComplianceFrameworkOption(BaseModel):
    framework: str
    framework_name: str
    # How many of this framework's distinct mapped checks have a finding in
    # the project the frameworks were requested for — the live "most-used"
    # ranking signal, not a static rulebook-size count.
    match_count: int


class ComplianceRequirementResult(BaseModel):
    requirement_id: str
    requirement_description: str | None
    check_ids: list[str]
    status: ComplianceRequirementStatus


class ComplianceReportSummary(BaseModel):
    passed: int
    failed: int
    needs_review: int
    not_assessed: int
    total_requirements: int
    # None when there is nothing to score against (passed + failed == 0) —
    # never a misleadingly perfect 100% for an unassessed framework.
    score_percent: int | None


class ComplianceReportResponse(BaseModel):
    framework: str
    framework_name: str
    summary: ComplianceReportSummary
    requirements: list[ComplianceRequirementResult]
