"""
MASVS Audit Copilot — Pydantic Schemas
Request/Response models for the API.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


# ═══════════════════════════════════════════
# AUTH SCHEMAS
# ═══════════════════════════════════════════

class UserRegister(BaseModel):
    """Registration request."""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    """Login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token pair response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefresh(BaseModel):
    """Refresh token request."""
    refresh_token: str


class UserResponse(BaseModel):
    """User profile response."""
    id: int
    email: str
    full_name: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ═══════════════════════════════════════════
# PROJECT SCHEMAS
# ═══════════════════════════════════════════

class ProjectCreate(BaseModel):
    """Create a new project."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    platform: Optional[str] = Field(None, pattern="^(android|ios|both)$")
    package_name: Optional[str] = None


class ProjectResponse(BaseModel):
    """Project response."""
    id: int
    name: str
    description: Optional[str]
    platform: Optional[str]
    package_name: Optional[str]
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ═══════════════════════════════════════════
# SCAN SCHEMAS
# ═══════════════════════════════════════════

class ScanUploadResponse(BaseModel):
    """Response after uploading an app for scanning."""
    job_id: int
    scan_id: int
    file_name: str
    status: str
    message: str


class ScanProgress(BaseModel):
    """Real-time scan progress update (WebSocket)."""
    scan_id: int
    status: str
    progress: int  # 0-100
    current_step: Optional[str] = None
    message: Optional[str] = None


class ScanResponse(BaseModel):
    """Complete scan result."""
    id: int
    project_id: int
    file_name: str
    file_hash: Optional[str]
    app_version: Optional[str]
    status: str
    progress: int
    score: Optional[float]
    grade: Optional[str]
    executive_summary: Optional[str] = None
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    findings_count: Optional[int] = None
    # Dynamic analysis fields
    scan_mode: str = "static"
    dynamic_status: str = "not_requested"
    dynamic_error: Optional[str] = None

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int


# ═══════════════════════════════════════════
# FINDING SCHEMAS
# ═══════════════════════════════════════════

class FindingResponse(BaseModel):
    """Single finding/vulnerability."""
    id: int
    scan_id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    masvs_category: Optional[str]
    masvs_control: Optional[str]
    mastg_test: Optional[str]
    cvss_vector: Optional[str]
    cvss_score: Optional[float]
    fingerprint: Optional[str]
    affected_file: Optional[str]
    affected_code: Optional[str]
    line_number: Optional[int]
    triage_result: str
    triage_justification: Optional[str]
    remediation_description: Optional[str]
    remediation_code: Optional[str]
    estimated_effort_hours: Optional[float] = None
    priority_label: Optional[str] = None
    jira_issue_key: Optional[str] = None
    # source values: "static" | "dynamic" | "frida" | "network"
    source: str = "static"
    mapping_confidence: Optional[float] = None
    semantic_group_id: Optional[str] = None
    root_cause: Optional[str] = None
    accepted_reason: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class FindingUpdateStatus(BaseModel):
    """Update the status of a finding."""
    status: str = Field(..., pattern="^(open|confirmed|false_positive|accepted_risk|fixed)$")
    reason: Optional[str] = None


# ═══════════════════════════════════════════
# DIFF SCHEMAS
# ═══════════════════════════════════════════

class DiffResponse(BaseModel):
    """Version comparison result."""
    scan_id_1: int
    scan_id_2: int
    new_findings: List[FindingResponse]
    fixed_findings: List[FindingResponse]
    persistent_findings: List[FindingResponse]
    score_change: Optional[float] = None


class AttackPathResponse(BaseModel):
    """Chained attack scenario derived from related findings."""
    id: int
    scan_id: int
    title: str
    description: str
    severity: str
    finding_ids: List[int]
    exploitability_score: Optional[float]
    created_at: datetime

    class Config:
        from_attributes = True
