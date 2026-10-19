from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class GcpOrganization(Base):
    __tablename__ = "gcp_organizations"
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
            "ix_gcp_organizations_org_id_active",
            "org_id",
            unique=True,
            postgresql_where=text("NOT deleted"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Uniqueness lives in a partial index over active rows only
    # (ix_gcp_organizations_org_id_active) rather than a plain column
    # constraint, so a deleted organization's id can be reused — hence no
    # unique=True here.
    org_id: Mapped[str] = mapped_column(String, nullable=False)
    department_id: Mapped[int] = mapped_column(Integer, ForeignKey("departments.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
