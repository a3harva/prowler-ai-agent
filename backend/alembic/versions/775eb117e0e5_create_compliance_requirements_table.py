"""create compliance_requirements table

Revision ID: 775eb117e0e5
Revises: a34335bfc9a3
Create Date: 2026-08-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '775eb117e0e5'
down_revision: Union[str, None] = 'a34335bfc9a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'compliance_requirements',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('framework', sa.String(), nullable=False),
        sa.Column('framework_name', sa.String(), nullable=False),
        sa.Column('requirement_id', sa.String(), nullable=False),
        sa.Column('requirement_description', sa.Text(), nullable=True),
        sa.Column('check_id', sa.String(), nullable=False),
        sa.Column('attributes', postgresql.JSONB(astext_type=sa.Text()), server_default='{}', nullable=False),
        sa.Column('prowler_version', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        # framework_name is part of the identity, not just framework — CIS
        # 2.0/3.0/4.0/5.0 all share FRAMEWORK="CIS" in the real files and
        # only differ by NAME (see app/models/compliance_requirement.py).
        sa.UniqueConstraint(
            'framework', 'framework_name', 'requirement_id', 'check_id',
            name='uq_compliance_requirements_identity',
        ),
    )
    op.create_index('ix_compliance_requirements_check_id', 'compliance_requirements', ['check_id'])
    op.create_index('ix_compliance_requirements_framework', 'compliance_requirements', ['framework'])

    op.add_column(
        'scans',
        sa.Column('compliance_drift_detected', sa.Boolean(), server_default='false', nullable=False),
    )


def downgrade() -> None:
    op.drop_column('scans', 'compliance_drift_detected')
    op.drop_index('ix_compliance_requirements_framework', table_name='compliance_requirements')
    op.drop_index('ix_compliance_requirements_check_id', table_name='compliance_requirements')
    op.drop_table('compliance_requirements')
