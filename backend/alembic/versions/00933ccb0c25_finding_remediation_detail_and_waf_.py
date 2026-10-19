"""finding remediation detail and waf pillar mapping

Revision ID: 00933ccb0c25
Revises: 775eb117e0e5
Create Date: 2026-08-19 16:22:32.920061

Hand-corrected after autogenerate. `--autogenerate` additionally proposed
dropping eleven existing indexes — the partial unique indexes behind the
soft-delete re-registration rule (`ix_departments_freshservice_id_active`,
`ix_gcp_organizations_org_id_active`, `ix_projects_project_id_active`) and the
findings/scans query indexes. They were created by earlier migrations in raw
SQL that autogenerate cannot reconcile against the model metadata, so it reads
them as orphans. Dropping them would have silently removed the constraint that
stops a deleted department's id being re-registered twice. Those statements are
deliberately deleted from this file; only the additive changes remain.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '00933ccb0c25'
down_revision: Union[str, None] = '775eb117e0e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mirrors app.models.waf_pillar_mapping.DEFAULT_PILLAR_MAPPING. Duplicated
# literally rather than imported: a migration must keep working when the
# application constant is later edited, and importing it would make this
# migration's result depend on whatever the code says at run time.
_SECURITY = "Security, Privacy & Compliance"
_SEED = [
    ("", _SECURITY),  # no category on the finding — the explicit fallback
    ("encryption", _SECURITY),
    ("identity-access", _SECURITY),
    ("internet-exposed", _SECURITY),
    ("secrets", _SECURITY),
    ("trust-boundaries", _SECURITY),
    ("vulnerabilities", _SECURITY),
    ("node-security", _SECURITY),
    ("container-security", _SECURITY),
    ("forensics-ready", _SECURITY),
    ("gen-ai", _SECURITY),
    ("logging", "Operational Excellence"),
    ("resilience", "Reliability"),
]


def upgrade() -> None:
    # Prowler's explanatory and remediation content, previously validated in
    # the CSV header check and then discarded. Nullable and additive: existing
    # rows keep NULL, and the report skips a finding that has none.
    op.add_column('findings', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('risk', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('remediation_text', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('remediation_url', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('remediation_cli', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('remediation_terraform', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('remediation_iac', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('categories', sa.String(), nullable=True))

    mapping = op.create_table(
        'waf_pillar_mapping',
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('pillar', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('category'),
    )
    # Static reference data with no file dependency, so it seeds here rather
    # than through an admin action — unlike the compliance rulebook, which
    # genuinely needs a scan's output on disk.
    op.bulk_insert(mapping, [{"category": c, "pillar": p} for c, p in _SEED])


def downgrade() -> None:
    op.drop_table('waf_pillar_mapping')
    for col in (
        'categories', 'remediation_iac', 'remediation_terraform', 'remediation_cli',
        'remediation_url', 'remediation_text', 'risk', 'description',
    ):
        op.drop_column('findings', col)
