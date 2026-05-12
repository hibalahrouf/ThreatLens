"""
MASVS Audit Copilot — Findings API Routes
PATCH  /api/findings/{id}/status    Update finding status (accept risk, suppress)
GET    /api/findings/{id}           Get single finding details
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import User, Finding, Scan, Project, FindingStatus, AuditorFeedback
from app.models.schemas import FindingResponse, FindingUpdateStatus
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the full details of a specific finding."""
    finding = (
        db.query(Finding)
        .join(Scan)
        .join(Project)
        .filter(Finding.id == finding_id, Project.user_id == current_user.id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: int,
    data: FindingUpdateStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update the status of a finding.

    Valid statuses: open, confirmed, false_positive, accepted_risk, fixed.
    Provide a reason when marking as accepted_risk or false_positive.
    """
    finding = (
        db.query(Finding)
        .join(Scan)
        .join(Project)
        .filter(Finding.id == finding_id, Project.user_id == current_user.id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate status transition
    try:
        new_status = FindingStatus(data.status)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{data.status}'",
        )

    # Require reason for risk acceptance
    if new_status == FindingStatus.ACCEPTED_RISK and not data.reason:
        raise HTTPException(
            status_code=400,
            detail="A reason is required when accepting a risk",
        )

    previous_status = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    previous_triage = finding.triage_result.value if hasattr(finding.triage_result, "value") else str(finding.triage_result)

    finding.status = new_status
    if data.reason:
        finding.accepted_reason = data.reason

    if previous_status != new_status.value:
        db.add(AuditorFeedback(
            finding_id=finding.id,
            original_triage=previous_triage,
            corrected_status=new_status.value,
            auditor_reason=data.reason,
            finding_title=finding.title,
            finding_description=finding.description,
            masvs_control=finding.masvs_control,
            affected_code=finding.affected_code,
        ))

    db.commit()
    db.refresh(finding)
    return FindingResponse.model_validate(finding)
