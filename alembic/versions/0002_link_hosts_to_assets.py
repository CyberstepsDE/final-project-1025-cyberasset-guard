"""link discovered hosts to managed assets

Adds monitoring assets.managed_asset_id (-> asset_inventory.id, a UUID string)
and an index for candidate/link lookups. Nullable, no server default and no DB
foreign key (managed assets are deactivated, never deleted). (ASSET-64)

The baseline (0001) creates the schema via create_all, which always reflects the
*current* models — so on a fresh database the column already exists by the time
this runs. It is therefore added conditionally: a no-op on fresh databases, and
the real upgrade on databases created before the column existed.

Revision ID: 0002_host_managed_asset
Revises: 0001_baseline
"""
import sqlalchemy as sa

from alembic import op

revision = "0002_host_managed_asset"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def _has_column(bind, table, column) -> bool:
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _has_index(bind, table, index) -> bool:
    return any(i["name"] == index for i in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "assets", "managed_asset_id"):
        op.add_column("assets", sa.Column("managed_asset_id", sa.String(), nullable=True))
    if not _has_index(bind, "assets", "ix_assets_managed_asset_id"):
        op.create_index("ix_assets_managed_asset_id", "assets", ["managed_asset_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if _has_index(bind, "assets", "ix_assets_managed_asset_id"):
        op.drop_index("ix_assets_managed_asset_id", table_name="assets")
    if _has_column(bind, "assets", "managed_asset_id"):
        op.drop_column("assets", "managed_asset_id")
