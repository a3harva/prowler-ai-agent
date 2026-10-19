import datetime
import enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class FindingStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    # Never present in scanner output — only ever written by the importer's
    # own absence sweep on a re-scan, when a previously-seen
    # identity no longer appears in the file.
    RESOURCE_DOES_NOT_EXIST = "RESOURCE_DOES_NOT_EXIST"


class MuteReason(str, enum.Enum):
    risk_accepted = "risk_accepted"
    false_positive = "false_positive"
    compensating_control = "compensating_control"
    remediation_in_progress = "remediation_in_progress"
    not_applicable = "not_applicable"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        # The identity key, and the ON CONFLICT target the importer upserts
        # against. Deliberately NOT the scanner's own FINDING_UID, which is
        # derived from RESOURCE_NAME rather than RESOURCE_UID and collides
        # for genuinely distinct resources — verified in the reference scan.
        # Region is deliberately excluded: it adds no uniqueness, and some
        # resources legitimately appear under several regions, so including
        # it would let a region relabel detach a mute.
        UniqueConstraint("project_id", "check_id", "resource_uid", name="uq_findings_identity"),
        CheckConstraint("NOT muted OR mute_reason IS NOT NULL", name="ck_findings_mute_reason_required"),
        # Declared here, not only in the migration that created it — an index
        # created with op.create_index() but never declared on the model reads
        # as an orphan to every future `alembic revision --autogenerate`, which
        # then proposes DROPPING it. See models/department.py for the full note.
        #
        # These four back the findings screen's faceted filtering, which always
        # narrows by project first and then by one of these dimensions.
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_project_status", "project_id", "status"),
        Index("ix_findings_project_service", "project_id", "service_name"),
        Index("ix_findings_project_muted", "project_id", "muted"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False)

    check_id: Mapped[str] = mapped_column(String, nullable=False)
    resource_uid: Mapped[str] = mapped_column(String, nullable=False)
    # Retained for display only — see the identity note above. Not unique.
    finding_uid: Mapped[str] = mapped_column(String, nullable=False)

    check_title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus, name="finding_status"), nullable=False)
    status_extended: Mapped[str | None] = mapped_column(Text, nullable=True)
    region: Mapped[str] = mapped_column(String, nullable=False)

    # The human-triage overlay. Never touched by the importer's upsert on an
    # existing row — enforced by the SQL itself (services/importer.py), not
    # by remembering to preserve it.
    muted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    mute_reason: Mapped[MuteReason | None] = mapped_column(Enum(MuteReason, name="mute_reason"), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    service_name: Mapped[str] = mapped_column(String, nullable=False)
    subservice_name: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)
    resource_name: Mapped[str] = mapped_column(String, nullable=False)

    # Prowler's own explanatory and remediation content, carried through from
    # the scan CSV so the AI report can reuse it verbatim rather than have a
    # model generate a `gcloud` command for a customer to run. Nullable
    # because they are additive: a row written by an importer older than this
    # change simply has none, and the report skips such findings rather than
    # rendering a hollow section.
    #
    # `categories` stays the raw pipe-separated Prowler string ("secrets |
    # identity-access"), not a parsed list — the pillar rule reads the first
    # tag, and keeping the original means a future rule can read the rest
    # without a re-scan.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_cli: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_terraform: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_iac: Mapped[str | None] = mapped_column(Text, nullable=True)
    categories: Mapped[str | None] = mapped_column(String, nullable=True)

    last_scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    first_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
