import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models import Base


class Department(Base):
    __tablename__ = "departments"
    __table_args__ = (
    # Declared here, not only in the migration that created it. Alembic
    # autogenerate diffs the models against the live database, so an index
    # created with op.create_index() but never declared on the model reads as
    # an orphan and every future --autogenerate proposes DROPPING it. It also
    # means Base.metadata.create_all() — which is how the test database is
    # built — never creates it, so the test schema silently diverges from the
    # real one and no test could catch the loss.
        #
        # This one is a correctness constraint, not a performance hint: it is
        # what stops two live departments sharing a freshservice_id, and what
        # closes the race the SELECT-then-INSERT in services/departments.py
        # cannot close on its own.
        Index(
            "ix_departments_freshservice_id_active",
            "freshservice_id",
            unique=True,
            postgresql_where=text("NOT deleted"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Uniqueness lives in a partial index over active rows only
    # (ix_departments_freshservice_id_active) rather than a plain column
    # constraint, so a deleted department's id can be reused — hence no
    # unique=True here.
    freshservice_id: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    domains: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
