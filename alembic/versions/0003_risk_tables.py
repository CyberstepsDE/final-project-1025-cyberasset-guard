"""risk engine tables

Adds finding_risk (stored risk assessment per correlation finding) and asset_risk
(aggregated risk per managed asset). (Risk on findings, PR #22)

The baseline (0001) creates the schema via create_all of the *current* models, so
on a fresh database these tables already exist when this runs. Like 0002 they are
therefore created conditionally: a no-op on fresh databases, the real upgrade on
databases that were already at 0002.

Revision ID: 0003_risk_tables
Revises: 0002_host_managed_asset
"""
import sqlalchemy as sa

from alembic import op
from app.database import UTCDateTime

revision = "0003_risk_tables"
down_revision = "0002_host_managed_asset"
branch_labels = None
depends_on = None


def _has_table(bind, table) -> bool:
    return sa.inspect(bind).has_table(table)


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "finding_risk"):
        op.create_table(
            "finding_risk",
            sa.Column("finding_id", sa.Integer(), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False),
            sa.Column("level", sa.String(length=10), nullable=False),
            sa.Column("factors", sa.Text(), nullable=False),
            sa.Column("unknown_factors", sa.Text(), nullable=False),
            sa.Column("why", sa.Text(), nullable=False),
            sa.Column("inputs", sa.Text(), nullable=False),
            sa.Column("model_version", sa.String(length=10), nullable=False),
            sa.Column("assessed_at", UTCDateTime(), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("finding_id"),
        )
    if not _has_table(bind, "asset_risk"):
        op.create_table(
            "asset_risk",
            sa.Column("asset_id", sa.String(length=36), nullable=False),
            sa.Column("assessed_at", UTCDateTime(), nullable=False),
            sa.Column("open_findings", sa.Integer(), nullable=False),
            sa.Column("accepted_findings", sa.Integer(), nullable=False),
            sa.Column("findings_with_unknowns", sa.Integer(), nullable=False),
            sa.Column("max_score", sa.Integer(), nullable=True),
            sa.Column("max_level", sa.String(length=10), nullable=True),
            sa.Column("correlation_warnings", sa.Text(), nullable=False),
            sa.Column("model_version", sa.String(length=10), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["asset_inventory.id"]),
            sa.PrimaryKeyConstraint("asset_id"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("asset_risk", "finding_risk"):
        if _has_table(bind, table):
            op.drop_table(table)
