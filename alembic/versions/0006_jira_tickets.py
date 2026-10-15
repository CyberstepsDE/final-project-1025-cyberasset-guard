"""jira ticket delivery records

Adds jira_tickets: one row per finding (UNIQUE finding_id - the idempotency anchor),
with the delivery state, Jira issue key/URL, attempts and the pending verification
note. (Automatic Jira ticket creation for qualifying findings)

The baseline (0001) creates the schema via create_all of the *current* models, so on a
fresh database the table already exists when this runs. Like 0002-0005 it is therefore
created conditionally.

Revision ID: 0006_jira_tickets
Revises: 0005_dashboard
"""
import sqlalchemy as sa

from alembic import op
from app.database import UTCDateTime

revision = "0006_jira_tickets"
down_revision = "0005_dashboard"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("jira_tickets"):
        return
    op.create_table(
        "jira_tickets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=10), nullable=False),
        sa.Column("trigger", sa.String(length=10), nullable=False),
        sa.Column("requested_by", sa.String(length=100), nullable=True),
        sa.Column("issue_key", sa.String(length=50), nullable=True),
        sa.Column("issue_url", sa.String(length=300), nullable=True),
        sa.Column("jira_status", sa.String(length=100), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", UTCDateTime(), nullable=True),
        sa.Column("lease_until", UTCDateTime(), nullable=True),
        sa.Column("last_attempt_at", UTCDateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("error_category", sa.String(length=20), nullable=True),
        sa.Column("note_pending", sa.Text(), nullable=True),
        sa.Column("note_attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.Column("synced_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
        sa.UniqueConstraint("label"),
    )
    op.create_index("ix_jira_tickets_state", "jira_tickets", ["state"])


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("jira_tickets"):
        op.drop_index("ix_jira_tickets_state", table_name="jira_tickets")
        op.drop_table("jira_tickets")
