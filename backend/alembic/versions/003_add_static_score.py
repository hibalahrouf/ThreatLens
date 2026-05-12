"""Add static_score to scans table

Revision ID: 003_add_static_score
Revises: 002_roadmap_enrichment
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


revision = "003_add_static_score"
down_revision = "002_roadmap_enrichment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("static_score", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "static_score")
