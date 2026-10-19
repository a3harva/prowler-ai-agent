"""report format warnings

Revision ID: c2d5f88b1e40
Revises: b1c4e77a9d02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c2d5f88b1e40'
down_revision: Union[str, None] = 'b1c4e77a9d02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('reports', sa.Column('format_warnings', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('reports', 'format_warnings')
