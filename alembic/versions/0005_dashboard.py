"""executive dashboard: posture snapshots and correlation run scope

- security_snapshots: one row per UTC day with the organisation-level posture
  (Security Score, open findings by risk level, coverage). Trends use only these
  persisted measurements - never values reconstructed from today's state.
- correlation_runs.scope: 'all' (every active asset) or 'selected'; NULL for runs
  recorded before this revision. Needed to tell a full assessment from a partial one.

Like 0002-0004 every step is conditional: a no-op on fresh databases (the baseline
creates the current models), the real upgrade on databases already at 0004.

Revision ID: 0005_dashboard
Revises: 0004_risk_history
"""
import sqlalchemy as sa

from alembic import op
from app.database import UTCDateTime

revision = "0005_dashboard"
down_revision = "0004_risk_history"
branch_labels = None
depends_on = None


def _has_column(bind, table, column) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("security_snapshots"):
        op.create_table(
            "security_snapshots",
            sa.Column("day", sa.Date(), nullable=False),
            sa.Column("taken_at", UTCDateTime(), nullable=False),
            sa.Column("security_score", sa.Integer(), nullable=True),
            sa.Column("method_version", sa.String(length=10), nullable=False),
            sa.Column("worst_asset_risk", sa.Integer(), nullable=True),
            sa.Column("assets_active", sa.Integer(), nullable=False),
            sa.Column("assets_assessed", sa.Integer(), nullable=False),
            sa.Column("assets_at_risk", sa.Integer(), nullable=False),
            sa.Column("open_findings", sa.Integer(), nullable=False),
            sa.Column("open_critical", sa.Integer(), nullable=False),
            sa.Column("open_high", sa.Integer(), nullable=False),
            sa.Column("open_medium", sa.Integer(), nullable=False),
            sa.Column("open_low", sa.Integer(), nullable=False),
            sa.Column("open_unscored", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("day"),
        )
    if not _has_column(bind, "correlation_runs", "scope"):
        op.add_column("correlation_runs", sa.Column("scope", sa.String(length=10), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind, "correlation_runs", "scope"):
        with op.batch_alter_table("correlation_runs") as batch:
            batch.drop_column("scope")
    if sa.inspect(bind).has_table("security_snapshots"):
        op.drop_table("security_snapshots")
