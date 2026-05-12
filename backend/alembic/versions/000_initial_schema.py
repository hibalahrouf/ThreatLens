"""Create initial application schema

Revision ID: 000_initial_schema
Revises:
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


revision = "000_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


scan_status = sa.Enum(
    "PENDING", "UPLOADING", "RUNNING", "ANALYZING",
    "GENERATING_REPORT", "DONE", "FAILED",
    name="scanstatus",
)
severity = sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity")
finding_status = sa.Enum(
    "OPEN", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "FIXED",
    name="findingstatus",
)
report_format = sa.Enum("PDF", "MARKDOWN", "SARIF", name="reportformat")
triage_result = sa.Enum(
    "TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW", "NOT_TRIAGED",
    name="triageresult",
)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("platform", sa.String(50), nullable=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_projects_id", "projects", ["id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("file_name", sa.String(500), nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=False),
        sa.Column("file_hash", sa.String(64), nullable=True),
        sa.Column("app_version", sa.String(50), nullable=True),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("progress", sa.Integer(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("grade", sa.String(2), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("mobsf_scan_hash", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_id", "scans", ["id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_project_status", "scans", ["project_id", "status"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", severity, nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("masvs_category", sa.String(50), nullable=True),
        sa.Column("masvs_control", sa.String(50), nullable=True),
        sa.Column("mastg_test", sa.String(100), nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True),
        sa.Column("affected_file", sa.String(500), nullable=True),
        sa.Column("affected_code", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("triage_result", triage_result, nullable=False),
        sa.Column("triage_justification", sa.Text(), nullable=True),
        sa.Column("remediation_description", sa.Text(), nullable=True),
        sa.Column("remediation_code", sa.Text(), nullable=True),
        sa.Column("source", sa.String(50), nullable=True),
        sa.Column("accepted_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_id", "findings", ["id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_scan_masvs", "findings", ["scan_id", "masvs_category"])
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("format", report_format, nullable=False),
        sa.Column("file_path", sa.String(1000), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_id", "reports", ["id"])


def downgrade() -> None:
    op.drop_index("ix_reports_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_index("ix_findings_scan_masvs", table_name="findings")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_index("ix_findings_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_scans_project_status", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_id", table_name="scans")
    op.drop_table("scans")

    op.drop_index("ix_projects_id", table_name="projects")
    op.drop_table("projects")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")

    triage_result.drop(op.get_bind(), checkfirst=True)
    report_format.drop(op.get_bind(), checkfirst=True)
    finding_status.drop(op.get_bind(), checkfirst=True)
    severity.drop(op.get_bind(), checkfirst=True)
    scan_status.drop(op.get_bind(), checkfirst=True)
