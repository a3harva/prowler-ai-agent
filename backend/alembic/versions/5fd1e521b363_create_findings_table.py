"""create findings table

Revision ID: 5fd1e521b363
Revises: cc869769bb6e
Create Date: 2026-08-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '5fd1e521b363'
down_revision: Union[str, None] = 'cc869769bb6e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


severity_enum = postgresql.ENUM(
    'critical', 'high', 'medium', 'low', 'informational', name='severity', create_type=False,
)
finding_status_enum = postgresql.ENUM(
    'PASS', 'FAIL', 'MANUAL', 'RESOURCE_DOES_NOT_EXIST', name='finding_status', create_type=False,
)
mute_reason_enum = postgresql.ENUM(
    'risk_accepted', 'false_positive', 'compensating_control',
    'remediation_in_progress', 'not_applicable', name='mute_reason', create_type=False,
)


def upgrade() -> None:
    # The build plan's Phase 1 also specifies GIN trigram indexes on
    # resource_name/check_title for free-text search — deliberately deferred
    # until a free-text search consumer is added. There is nothing to index yet.
    severity_enum.create(op.get_bind(), checkfirst=True)
    finding_status_enum.create(op.get_bind(), checkfirst=True)
    mute_reason_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('check_id', sa.String(), nullable=False),
        sa.Column('resource_uid', sa.String(), nullable=False),
        sa.Column('finding_uid', sa.String(), nullable=False),
        sa.Column('check_title', sa.String(), nullable=False),
        sa.Column('severity', severity_enum, nullable=False),
        sa.Column('status', finding_status_enum, nullable=False),
        sa.Column('status_extended', sa.Text(), nullable=True),
        sa.Column('region', sa.String(), nullable=False),
        sa.Column('muted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mute_reason', mute_reason_enum, nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('service_name', sa.String(), nullable=False),
        sa.Column('subservice_name', sa.String(), nullable=True),
        sa.Column('resource_type', sa.String(), nullable=False),
        sa.Column('resource_name', sa.String(), nullable=False),
        sa.Column('last_scan_id', sa.Integer(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
        sa.ForeignKeyConstraint(['last_scan_id'], ['scans.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', 'check_id', 'resource_uid', name='uq_findings_identity'),
        sa.CheckConstraint('NOT muted OR mute_reason IS NOT NULL', name='ck_findings_mute_reason_required'),
    )
    op.create_index('ix_findings_project_status', 'findings', ['project_id', 'status'])
    op.create_index('ix_findings_project_severity', 'findings', ['project_id', 'severity'])
    op.create_index('ix_findings_project_muted', 'findings', ['project_id', 'muted'])
    op.create_index('ix_findings_project_service', 'findings', ['project_id', 'service_name'])


def downgrade() -> None:
    op.drop_index('ix_findings_project_service', table_name='findings')
    op.drop_index('ix_findings_project_muted', table_name='findings')
    op.drop_index('ix_findings_project_severity', table_name='findings')
    op.drop_index('ix_findings_project_status', table_name='findings')
    op.drop_table('findings')
    mute_reason_enum.drop(op.get_bind(), checkfirst=True)
    finding_status_enum.drop(op.get_bind(), checkfirst=True)
    severity_enum.drop(op.get_bind(), checkfirst=True)
