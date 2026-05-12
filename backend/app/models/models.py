"""
MASVS Audit Copilot — SQLAlchemy ORM Models
Defines the database schema for the application.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Enum,
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base


# ─── Enums ───

class ScanStatus(str, enum.Enum):
    """Status of a security scan job."""
    PENDING = "pending"
    UPLOADING = "uploading"
    RUNNING = "running"
    ANALYZING = "analyzing"
    GENERATING_REPORT = "generating_report"
    DONE = "done"
    FAILED = "failed"


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Status of an individual finding."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class ReportFormat(str, enum.Enum):
    """Supported report export formats."""
    PDF = "pdf"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class TriageResult(str, enum.Enum):
    """LLM triage decision for a finding."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    NOT_TRIAGED = "not_triaged"


# ─── Utility ───

def utcnow():
    return datetime.now(timezone.utc)


# ─── Models ───

class User(Base):
    """Application user (auditor / developer)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"


class Project(Base):
    """A mobile application project that groups multiple scans."""
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    platform = Column(String(50), nullable=True)  # android / ios / both
    package_name = Column(String(255), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}')>"


class Scan(Base):
    """A single security scan of an APK or IPA file."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    file_name = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)  # MinIO object path
    file_hash = Column(String(64), nullable=True)  # SHA-256 of the uploaded file
    app_version = Column(String(50), nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = Column(Integer, default=0)  # 0-100 percentage
    score = Column(Float, nullable=True)  # Global security score (0-100)
    grade = Column(String(2), nullable=True)  # A+ / A / B / C / D / F
    static_score = Column(Float, nullable=True)  # Score from static analysis only (before dynamic)
    executive_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    mobsf_scan_hash = Column(String(64), nullable=True)  # MobSF internal hash
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # ─── Dynamic Analysis ───
    # scan_mode values: "static" | "dynamic"
    scan_mode = Column(String(20), nullable=False, default="static", server_default="static")
    # dynamic_status values: "not_requested" | "queued" | "running" | "completed" | "failed"
    dynamic_status = Column(String(20), nullable=False, default="not_requested", server_default="not_requested")
    # dynamic_error: nullable, contains error message if dynamic_status == "failed"
    dynamic_error = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index("ix_scans_project_status", "project_id", "status"),
    )

    def __repr__(self):
        return f"<Scan(id={self.id}, status='{self.status}', score={self.score})>"


class Finding(Base):
    """A single security finding/vulnerability discovered during a scan."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    # ─── Identification ───
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(Severity), nullable=False, index=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)

    # ─── MASVS Mapping ───
    masvs_category = Column(String(50), nullable=True)  # e.g., MASVS-STORAGE
    masvs_control = Column(String(50), nullable=True)  # e.g., MASVS-STORAGE-1
    mastg_test = Column(String(100), nullable=True)  # e.g., MASTG-TEST-0001

    # ─── CVSS Scoring ───
    cvss_vector = Column(String(200), nullable=True)
    cvss_score = Column(Float, nullable=True)

    # ─── Fingerprint (for version diff) ───
    fingerprint = Column(String(64), nullable=True, index=True)

    # ─── Evidence ───
    affected_file = Column(String(500), nullable=True)
    affected_code = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)

    # ─── LLM Triage ───
    triage_result = Column(
        Enum(TriageResult), default=TriageResult.NOT_TRIAGED, nullable=False
    )
    triage_justification = Column(Text, nullable=True)

    # ─── LLM Remediation ───
    remediation_description = Column(Text, nullable=True)
    remediation_code = Column(Text, nullable=True)  # Code diff in Kotlin/Swift
    estimated_effort_hours = Column(Float, nullable=True)
    priority_label = Column(String(20), nullable=True)
    jira_issue_key = Column(String(50), nullable=True)

    # ─── Metadata ───
    # source values: "static" | "dynamic" | "frida" | "network"
    source = Column(String(50), nullable=False, default="static", server_default="static")
    mapping_confidence = Column(Float, nullable=True)
    semantic_group_id = Column(String(64), nullable=True, index=True)
    root_cause = Column(Text, nullable=True)
    accepted_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    # Indexes
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_masvs", "scan_id", "masvs_category"),
    )

    def __repr__(self):
        return f"<Finding(id={self.id}, title='{self.title}', severity='{self.severity}')>"


class Report(Base):
    """A generated report file (PDF, Markdown, or SARIF)."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    format = Column(Enum(ReportFormat), nullable=False)
    file_path = Column(String(1000), nullable=False)  # MinIO object path
    file_size = Column(Integer, nullable=True)  # bytes
    created_at = Column(DateTime(timezone=True), default=utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="reports")

    def __repr__(self):
        return f"<Report(id={self.id}, format='{self.format}')>"


class AttackPath(Base):
    """A chained attack scenario derived from related findings."""
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), nullable=False, index=True)
    finding_ids = Column(Text, nullable=False)  # JSON array of finding IDs
    exploitability_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan", back_populates="attack_paths")

    def __repr__(self):
        return f"<AttackPath(id={self.id}, scan_id={self.scan_id}, severity='{self.severity}')>"


class AuditorFeedback(Base):
    """Human correction captured when auditors override finding state."""
    __tablename__ = "auditor_feedback"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    original_triage = Column(String(50), nullable=True)
    corrected_status = Column(String(50), nullable=False)
    auditor_reason = Column(Text, nullable=True)
    finding_title = Column(String(500), nullable=False)
    finding_description = Column(Text, nullable=True)
    masvs_control = Column(String(50), nullable=True, index=True)
    affected_code = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    def __repr__(self):
        return f"<AuditorFeedback(id={self.id}, finding_id={self.finding_id})>"
