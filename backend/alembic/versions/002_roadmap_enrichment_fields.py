"""Add roadmap enrichment fields and attack paths

Revision ID: 002_roadmap_enrichment
Revises: 001_dynamic_analysis
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


revision = "002_roadmap_enrichment"
down_revision = "001_dynamic_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("executive_summary", sa.Text(), nullable=True))

    op.add_column("findings", sa.Column("estimated_effort_hours", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("priority_label", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("jira_issue_key", sa.String(50), nullable=True))
    op.add_column("findings", sa.Column("mapping_confidence", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("semantic_group_id", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("root_cause", sa.Text(), nullable=True))
    op.create_index("ix_findings_semantic_group_id", "findings", ["semantic_group_id"])

    op.create_table(
        "attack_paths",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("finding_ids", sa.Text(), nullable=False),
        sa.Column("exploitability_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_paths_id", "attack_paths", ["id"])
    op.create_index("ix_attack_paths_scan_id", "attack_paths", ["scan_id"])
    op.create_index("ix_attack_paths_severity", "attack_paths", ["severity"])

    op.create_table(
        "auditor_feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("original_triage", sa.String(50), nullable=True),
        sa.Column("corrected_status", sa.String(50), nullable=False),
        sa.Column("auditor_reason", sa.Text(), nullable=True),
        sa.Column("finding_title", sa.String(500), nullable=False),
        sa.Column("finding_description", sa.Text(), nullable=True),
        sa.Column("masvs_control", sa.String(50), nullable=True),
        sa.Column("affected_code", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auditor_feedback_id", "auditor_feedback", ["id"])
    op.create_index("ix_auditor_feedback_finding_id", "auditor_feedback", ["finding_id"])
    op.create_index("ix_auditor_feedback_masvs_control", "auditor_feedback", ["masvs_control"])


def downgrade() -> None:
    op.drop_index("ix_auditor_feedback_masvs_control", table_name="auditor_feedback")
    op.drop_index("ix_auditor_feedback_finding_id", table_name="auditor_feedback")
    op.drop_index("ix_auditor_feedback_id", table_name="auditor_feedback")
    op.drop_table("auditor_feedback")

    op.drop_index("ix_attack_paths_severity", table_name="attack_paths")
    op.drop_index("ix_attack_paths_scan_id", table_name="attack_paths")
    op.drop_index("ix_attack_paths_id", table_name="attack_paths")
    op.drop_table("attack_paths")

    op.drop_index("ix_findings_semantic_group_id", table_name="findings")
    op.drop_column("findings", "root_cause")
    op.drop_column("findings", "semantic_group_id")
    op.drop_column("findings", "mapping_confidence")
    op.drop_column("findings", "jira_issue_key")
    op.drop_column("findings", "priority_label")
    op.drop_column("findings", "estimated_effort_hours")

    op.drop_column("scans", "executive_summary")
