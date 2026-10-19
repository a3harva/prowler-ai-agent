"""soft delete for departments, gcp_organizations, projects

Revision ID: cc869769bb6e
Revises: d8f89250715d
Create Date: 2026-08-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cc869769bb6e'
down_revision: Union[str, None] = 'd8f89250715d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # departments: archived -> deleted, and the natural-key uniqueness moves
    # from a plain constraint to a partial index over active rows only — a
    # deleted row's freshservice_id stops being globally reserved, which is
    # the actual fix for "archive then re-add fails with already exists".
    op.alter_column('departments', 'archived', new_column_name='deleted')
    op.drop_constraint('departments_freshservice_id_key', 'departments', type_='unique')
    op.create_index(
        'ix_departments_freshservice_id_active', 'departments', ['freshservice_id'],
        unique=True, postgresql_where=sa.text('NOT deleted'),
    )

    # projects: same rename + same partial-index treatment for project_id.
    op.alter_column('projects', 'archived', new_column_name='deleted')
    op.drop_constraint('projects_project_id_key', 'projects', type_='unique')
    op.create_index(
        'ix_projects_project_id_active', 'projects', ['project_id'],
        unique=True, postgresql_where=sa.text('NOT deleted'),
    )

    # gcp_organizations had no archived column or independent lifecycle. Add
    # `deleted` fresh, then the same partial-index treatment for org_id.
    op.add_column(
        'gcp_organizations',
        sa.Column('deleted', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.drop_constraint('gcp_organizations_org_id_key', 'gcp_organizations', type_='unique')
    op.create_index(
        'ix_gcp_organizations_org_id_active', 'gcp_organizations', ['org_id'],
        unique=True, postgresql_where=sa.text('NOT deleted'),
    )


def downgrade() -> None:
    op.drop_index('ix_gcp_organizations_org_id_active', table_name='gcp_organizations')
    op.create_unique_constraint('gcp_organizations_org_id_key', 'gcp_organizations', ['org_id'])
    op.drop_column('gcp_organizations', 'deleted')

    op.drop_index('ix_projects_project_id_active', table_name='projects')
    op.create_unique_constraint('projects_project_id_key', 'projects', ['project_id'])
    op.alter_column('projects', 'deleted', new_column_name='archived')

    op.drop_index('ix_departments_freshservice_id_active', table_name='departments')
    op.create_unique_constraint('departments_freshservice_id_key', 'departments', ['freshservice_id'])
    op.alter_column('departments', 'deleted', new_column_name='archived')
