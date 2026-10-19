import datetime
import enum

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class ReportStatus(str, enum.Enum):
    queued = "queued"
    generating = "generating"
    completed = "completed"
    failed = "failed"


class ReportMode(str, enum.Enum):
    """How the report's prose was produced.

    `standard` is the original single-pass pipeline: one Gemini call per
    pillar, one summary call, render. `deep` runs the LangGraph agent in
    `app/agents/` — it investigates with tools, correlates across pillars and
    plans remediation sequencing before composing.

    Stored on the row rather than inferred, for the same reason
    `include_muted` is: a report must stay reproducible, and a reader needs to
    know which pipeline produced the document in front of them. The two modes
    render the *same facts* — the ledger guarantees that — but different
    prose and a different section set.
    """

    standard = "standard"
    deep = "deep"


class Report(Base):
    """One AI-written assessment report for one project.

    **One project per report is a hard constraint, not a v1 simplification** —
    hence a singular `project_id` FK rather than an association table. Combined
    multi-project reports were tried before and worked for neither the customer
    nor the engineers scoping the work; the constraint is repeated inside the
    model's own prompt so it cannot reason across projects either.

    The Markdown lives in `content` rather than at a path on disk. `/reports` is
    not covered by `scripts/db-backup.sh`, and a customer-facing deliverable that
    exists only in an unbacked-up directory is one `docker-down.sh --volumes`
    from gone. Reports are prose — a fifty-check report is well under a megabyte.

    `scan_id` is provenance, not a filter: the report body is built from the
    project's *current* findings, and this records which scan was most recently
    succeeded when it was requested.
    """

    __tablename__ = "reports"
    __table_args__ = (
        # Declared here as well as in the migration: an index that exists only
        # in a migration reads as an orphan to the next autogenerate. Caught by
        # the empty-diff check in tests/test_alembic_checkpoint_tables.py.
        Index("ix_reports_project_id", "project_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)

    # Shown to the user the moment they click Generate, so they have something
    # to refer to before the row has any content. Human-quotable, unlike an id.
    task_reference_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)

    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=False
    )
    requested_by_user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)

    # Written once, on success. A failed report stores nothing: the generator is
    # all-or-nothing, matching the import pipeline, because a half-written
    # customer-facing document is worse than a clear failure to retry.
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Built once, in the same Celery task that builds `content`, from the
    # same in-memory payload/narratives/executive_summary — no drift between
    # the two artifacts. Lives in Postgres for the same backup reasoning as
    # `content` above, not on the unbacked-up `/reports` disk directory.
    pdf_content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # How many findings were left out because they predate remediation-detail
    # capture, and how many carried a category the mapping table doesn't know.
    # Surfaced so drift is noticed without failing generation.
    skipped_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    unknown_category_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Which pipeline produced this report. NOT NULL with a server default so
    # every pre-existing row reads as `standard`, which is what they are.
    mode: Mapped[ReportMode] = mapped_column(
        Enum(ReportMode, name="report_mode"), nullable=False, server_default="standard"
    )

    # Free-text guidance from the requester, e.g. "the customer cares most
    # about data exfiltration paths — lead with those". Steers emphasis and
    # tone only: it is fenced as untrusted input in the prompts and cannot
    # override the scope rule, the verbatim-remediation rule, or coverage.
    # A user asking to "skip the low severity findings" changes what the prose
    # dwells on and changes nothing about which sections render, because the
    # ledger drives that loop and gate C1 requires every check to be covered.
    instructions: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The deep mode's model-authored artifacts — themes, remediation waves,
    # per-pillar analysis, per-check prose — as they were at render time.
    # Stored so a report is inspectable and reproducible after the fact, and
    # so a disputed sentence can be traced to the artifact that produced it.
    # Null for `standard` reports.
    analysis: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Which deterministic gates ran and what they found. A record that the
    # count guarantee was actually checked on this document, rather than a
    # belief that it was.
    verification: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # The critique pass's verdict. Recorded, never obeyed — same posture as
    # `format_warnings` below: a model's opinion is evidence for a human, not
    # a gate on a customer-facing artifact.
    critique: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Live cloud state as it was at render time: the recon snapshot, the full
    # command log (successes, refusals and failures, each with an evidence_id),
    # and a `status` of complete / partial / unavailable.
    #
    # **The status is here because recon is always on.** An opt-in flag would
    # have doubled as the record that live context was attempted; without one,
    # a report whose recon failed silently would be indistinguishable from one
    # that never had it — the worst outcome for a document whose value is that
    # it was checked against reality. Null for a `standard` report, and for a
    # deep report generated before this column existed.
    live_context: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # The LangGraph thread this report's run lives on, so an interrupted run
    # can be resumed rather than restarted. Equal to `task_reference_id` in
    # practice; stored separately because they mean different things and one
    # is a user-facing label.
    graph_thread_id: Mapped[str | None] = mapped_column(String, nullable=True)

    # Whether muted findings were included when this report was built. Stored
    # rather than assumed, so a report stays reproducible and the UI can say
    # which mode produced it — the same document generated either way differs by
    # an order of magnitude on a heavily-muted project.
    include_muted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    # Advisory formatting notes from the model review pass, as a JSON list.
    # Never fatal: the deterministic validator in services/report_render.py is
    # what can fail a report, because a model's opinion about formatting is not
    # something a customer-facing artifact should hinge on.
    format_warnings: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Null means "as generated by the pipeline." Set means a human corrected
    # the text afterward via the edit endpoint — the ledger gates (C1-C6, see
    # agents/report_ledger.py) ran once at generation time and are never re-checked against
    # `content` after this, so this timestamp is what tells a reader the
    # document in front of them may no longer be exactly what the pipeline
    # produced and verified.
    content_edited_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def has_pdf(self) -> bool:
        """What API schemas expose — never `pdf_content` itself, which would
        have FastAPI attempt to JSON-serialize raw bytes on every fetch."""
        return self.pdf_content is not None
