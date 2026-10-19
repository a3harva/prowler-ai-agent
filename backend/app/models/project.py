import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
    # Declared here, not only in the migration that created it. Alembic
    # autogenerate diffs the models against the live database, so an index
    # created with op.create_index() but never declared on the model reads as
    # an orphan and every future --autogenerate proposes DROPPING it. It also
    # means Base.metadata.create_all() — which is how the test database is
    # built — never creates it, so the test schema silently diverges from the
    # real one and no test could catch the loss.
        #
        # A correctness constraint, not a performance hint — see Department.
        Index(
            "ix_projects_project_id_active",
            "project_id",
            unique=True,
            postgresql_where=text("NOT deleted"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Uniqueness lives in a partial index over active rows only
    # (ix_projects_project_id_active) rather than a plain column constraint,
    # so a deleted project's id can be reused — hence no unique=True here.
    project_id: Mapped[str] = mapped_column(String, nullable=False)
    gcp_organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("gcp_organizations.id"), nullable=False
    )
    target_sa_email: Mapped[str] = mapped_column(String, nullable=False)
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
