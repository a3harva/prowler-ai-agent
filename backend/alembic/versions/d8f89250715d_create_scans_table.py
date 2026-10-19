"""create scans table

Revision ID: d8f89250715d
Revises: 113d6c0aa7db
Create Date: 2026-08-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'd8f89250715d'
down_revision: Union[str, None] = '113d6c0aa7db'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# create_type=False: the type is created explicitly below via .create(), once.
# Without it, op.create_table's own column-DDL handling issues a second
# CREATE TYPE for the same name and fails with "already exists" even though
# this call site passes checkfirst=True — checkfirst there only guards
# against *this* call finding a preexisting type, not against create_table's
# separate, unconditional attempt to create the same one.
scan_status = postgresql.ENUM(
    'queued',
    'running',
    'importing',
    'succeeded',
    'failed',
    'timeout',
    'schema_mismatch',
    'import_failed',
    name='scan_status',
    create_type=False,
)


def upgrade() -> None:
    scan_status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('status', scan_status, nullable=False),
        sa.Column('sa_impersonated', sa.String(), nullable=True),
        sa.Column('triggered_by_user_id', sa.Integer(), nullable=False),
        sa.Column('triggered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('pass_count', sa.Integer(), nullable=True),
        sa.Column('fail_count', sa.Integer(), nullable=True),
        sa.Column('reports_path', sa.String(), nullable=True),
        sa.Column('container_id', sa.String(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.ForeignKeyConstraint(['triggered_by_user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scans_project_id', 'scans', ['project_id'])
    op.create_index('ix_scans_status', 'scans', ['status'])


def downgrade() -> None:
    op.drop_index('ix_scans_status', table_name='scans')
    op.drop_index('ix_scans_project_id', table_name='scans')
    op.drop_table('scans')
    scan_status.drop(op.get_bind(), checkfirst=True)
