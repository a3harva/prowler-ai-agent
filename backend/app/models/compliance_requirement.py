import datetime

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class ComplianceRequirement(Base):
    """The project-independent rulebook: which check satisfies which
    requirement of which framework, plus the requirement's descriptive
    text. Never carries a result (STATUS, RESOURCEID, ...) or a project
    identifier — see `services/compliance.py::seed_rulebook_from_scan`, the
    only place this table is ever written, which replaces its full
    contents atomically on each load."""

    __tablename__ = "compliance_requirements"
    __table_args__ = (
        # `framework_name` has to be part of the identity, not just
        # `framework` — verified against the real reference files: CIS
        # 2.0/3.0/4.0/5.0 all carry the identical FRAMEWORK value ("CIS"),
        # and only differ in NAME ("CIS ... Benchmark v2.0.0" vs "v3.0.0"
        # ...). Keying on `framework` alone silently merged all four
        # versions into one and crashed the load on the first duplicate
        # (framework, requirement_id, check_id) it hit.
        UniqueConstraint(
            "framework", "framework_name", "requirement_id", "check_id",
            name="uq_compliance_requirements_identity",
        ),
        # Declared here, not only in the migration that created it — an index
        # created with op.create_index() but never declared on the model reads
        # as an orphan to every future `alembic revision --autogenerate`, which
        # then proposes DROPPING it. See models/department.py for the full note.
        Index("ix_compliance_requirements_framework", "framework"),
        Index("ix_compliance_requirements_check_id", "check_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    framework: Mapped[str] = mapped_column(String, nullable=False)
    framework_name: Mapped[str] = mapped_column(String, nullable=False)
    requirement_id: Mapped[str] = mapped_column(String, nullable=False)
    requirement_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    check_id: Mapped[str] = mapped_column(String, nullable=False)
    # Every REQUIREMENTS_ATTRIBUTES_* (and framework-specific extra) column
    # the source file carried, keyed by its lowercased header — so there
    # is no per-framework code: one column instead of twenty-
    # one shapes of table.
    attributes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    # Tags the whole load — compared against on the next load to answer
    # "did seeding actually happen after the scanner was upgraded".
    prowler_version: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
