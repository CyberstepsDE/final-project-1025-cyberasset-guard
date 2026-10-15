"""risk history table

Adds asset_risk_history: one entry per change of an asset's risk, with its trigger
(assessment run, KEV refresh, finding status, asset change). (Assessment, step 4)

The baseline (0001) creates the schema via create_all of the *current* models, so
on a fresh database this table already exists when this runs. Like 0002/0003 it is
therefore created conditionally: a no-op on fresh databases, the real upgrade on
databases that were already at 0003.

Revision ID: 0004_risk_history
Revises: 0003_risk_tables
"""
import sqlalchemy as sa

from alembic import op
from app.database import UTCDateTime

revision = "0004_risk_history"
down_revision = "0003_risk_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("asset_risk_history"):
        return
    op.create_table(
        "asset_risk_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("recorded_at", UTCDateTime(), nullable=False),
        sa.Column("trigger", sa.String(length=30), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("max_score", sa.Integer(), nullable=True),
        sa.Column("max_level", sa.String(length=10), nullable=True),
        sa.Column("open_findings", sa.Integer(), nullable=False),
        sa.Column("accepted_findings", sa.Integer(), nullable=False),
        sa.Column("correlation_warnings", sa.Text(), nullable=False),
        sa.Column("model_version", sa.String(length=10), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["asset_inventory.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_risk_history_asset", "asset_risk_history", ["asset_id", "id"])


def downgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table("asset_risk_history"):
        op.drop_index("ix_asset_risk_history_asset", table_name="asset_risk_history")
        op.drop_table("asset_risk_history")
