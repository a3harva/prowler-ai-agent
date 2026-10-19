import datetime
import enum

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    importing = "importing"
    succeeded = "succeeded"
    failed = "failed"
    timeout = "timeout"
    schema_mismatch = "schema_mismatch"
    import_failed = "import_failed"
    cancelled = "cancelled"


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
    # Declared here, not only in the migration that created it. Alembic
    # autogenerate diffs the models against the live database, so an index
    # created with op.create_index() but never declared on the model reads as
    # an orphan and every future --autogenerate proposes DROPPING it. It also
    # means Base.metadata.create_all() — which is how the test database is
    # built — never creates it, so the test schema silently diverges from the
    # real one and no test could catch the loss.
        Index("ix_scans_project_id", "project_id"),
        Index("ix_scans_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.queued
    )
    # Snapshotted at submit time from projects.target_sa_email, so the record
    # of what was impersonated survives the project's SA being changed later.
    sa_impersonated: Mapped[str | None] = mapped_column(String, nullable=True)
    triggered_by_user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    triggered_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pass_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fail_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Worker-internal path (REPORTS_PATH/{id}), not the host path — this is
    # what the importer reads from.
    reports_path: Mapped[str | None] = mapped_column(String, nullable=True)
    container_id: Mapped[str | None] = mapped_column(String, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Last ~2KB of scanner output plus exit code — enough for an Editor to
    # diagnose an IAM/permission failure without shell access to the host.
    # The full log is kept alongside the scan on disk, at reports_path/prowler.log.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Set by the importer's drift guard: the scan's own inline
    # COMPLIANCE mappings were sampled against the loaded rulebook and most
    # of them weren't found — the real-world trigger is upgrading Prowler
    # and forgetting to reload the rulebook. False (never null) when no
    # rulebook is loaded yet, since there is nothing to drift against.
    compliance_drift_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
