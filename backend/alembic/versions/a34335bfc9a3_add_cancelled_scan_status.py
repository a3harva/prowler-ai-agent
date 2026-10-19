"""add cancelled scan status

Revision ID: a34335bfc9a3
Revises: 5fd1e521b363
Create Date: 2026-08-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'a34335bfc9a3'
down_revision: Union[str, None] = '5fd1e521b363'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ALTER TYPE ... ADD VALUE cannot run inside the transaction Alembic
    # wraps migrations in by default (Postgres forbids using a new enum
    # value in the same transaction that added it, and errors even before
    # that if the ADD VALUE itself is transactional) — autocommit_block()
    # steps outside that wrapper for this one statement.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'cancelled'")


def downgrade() -> None:
    # Postgres has no DROP VALUE for enums. Downgrading would require
    # rebuilding the type (rename, create, cast every column, drop old) —
    # not attempted here since nothing in this migration set has ever
    # needed a real downgrade path exercised for an enum-only change, and
    # doing it wrong risks the data it would be "protecting". A 'cancelled'
    # row existing is a correctness fact, not cosmetic, so silently
    # reassigning it to another status on downgrade would be worse than
    # refusing to.
    raise NotImplementedError(
        "downgrade not supported: Postgres cannot drop an enum value; "
        "rebuilding the scan_status type would require deciding what to do "
        "with any row already in the 'cancelled' state"
    )
