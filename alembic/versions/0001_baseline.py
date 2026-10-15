"""baseline: the current schema (create_all + audit triggers)

The baseline creates the schema by delegating to the application's models
(Base.metadata.create_all), so `alembic upgrade head` on an empty database
produces exactly the schema the app created before Alembic existed — the same
tables, indexes, CHECK constraints and audit_events append-only triggers. On a
database that already has these tables (create_all is create-if-not-exists) it
changes nothing and simply records the baseline revision.

Revision ID: 0001_baseline
Revises:
"""
from alembic import op
from app import database

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    database._register_all_models()
    database.Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    database._register_all_models()
    database.Base.metadata.drop_all(bind=op.get_bind())
