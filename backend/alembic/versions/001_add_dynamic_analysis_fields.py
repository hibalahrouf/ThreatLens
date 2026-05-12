"""Add dynamic analysis fields to scans and findings

Revision ID: 001_dynamic_analysis
Revises:
Create Date: 2026-05-03

Step 1 of 5: Schema-only changes for dynamic analysis support.
Adds scan_mode, dynamic_status, dynamic_error to scans table.
Updates findings.source to NOT NULL with server_default='static'.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "001_dynamic_analysis"
down_revision = "000_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── scans table ───
    op.add_column(
        "scans",
        sa.Column("scan_mode", sa.String(20), nullable=False, server_default="static"),
    )
    op.add_column(
        "scans",
        sa.Column(
            "dynamic_status",
            sa.String(20),
            nullable=False,
            server_default="not_requested",
        ),
    )
    op.add_column(
        "scans",
        sa.Column("dynamic_error", sa.Text(), nullable=True),
    )

    # ─── findings table ───
    # Backfill existing NULL source values before making column NOT NULL
    op.execute("UPDATE findings SET source = 'static' WHERE source IS NULL")
    op.alter_column(
        "findings",
        "source",
        existing_type=sa.String(50),
        nullable=False,
        server_default="static",
    )


def downgrade() -> None:
    # ─── findings table ───
    op.alter_column(
        "findings",
        "source",
        existing_type=sa.String(50),
        nullable=True,
        server_default=None,
    )

    # ─── scans table ───
    op.drop_column("scans", "dynamic_error")
    op.drop_column("scans", "dynamic_status")
    op.drop_column("scans", "scan_mode")
