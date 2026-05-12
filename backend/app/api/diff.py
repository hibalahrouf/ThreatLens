"""
MASVS Audit Copilot — Diff API Route
GET /api/scans/{scan_id}/diff?compare={scan_id_2}
Compare findings between two scan versions.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import User, Scan, Finding, Project
from app.models.schemas import FindingResponse, DiffResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/scans", tags=["diff"])


@router.get("/{scan_id}/diff", response_model=DiffResponse)
async def diff_scans(
    scan_id: int,
    compare: int = Query(..., description="Scan ID to compare against"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Compare two scans and return the delta:
    - **new_findings**: Vulnerabilities introduced in the newer scan
    - **fixed_findings**: Vulnerabilities present in the older scan but not the newer
    - **persistent_findings**: Vulnerabilities present in both scans
    - **score_change**: Difference in security score

    Both scans must belong to the current user.
    """
    # Fetch both scans
    scan_1 = (
        db.query(Scan).join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    scan_2 = (
        db.query(Scan).join(Project)
        .filter(Scan.id == compare, Project.user_id == current_user.id)
        .first()
    )

    if not scan_1:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if not scan_2:
        raise HTTPException(status_code=404, detail=f"Scan {compare} not found")

    # Load findings with fingerprints
    findings_1 = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_2 = db.query(Finding).filter(Finding.scan_id == compare).all()

    # Build fingerprint sets
    fp_map_1 = {f.fingerprint: f for f in findings_1 if f.fingerprint}
    fp_map_2 = {f.fingerprint: f for f in findings_2 if f.fingerprint}

    fp_set_1 = set(fp_map_1.keys())
    fp_set_2 = set(fp_map_2.keys())

    # Calculate diff
    new_fps = fp_set_2 - fp_set_1
    fixed_fps = fp_set_1 - fp_set_2
    persistent_fps = fp_set_1 & fp_set_2

    new_findings = [FindingResponse.model_validate(fp_map_2[fp]) for fp in new_fps]
    fixed_findings = [FindingResponse.model_validate(fp_map_1[fp]) for fp in fixed_fps]
    persistent_findings = [FindingResponse.model_validate(fp_map_2[fp]) for fp in persistent_fps]

    # Score change
    score_change = None
    if scan_1.score is not None and scan_2.score is not None:
        score_change = scan_2.score - scan_1.score

    return DiffResponse(
        scan_id_1=scan_id,
        scan_id_2=compare,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        persistent_findings=persistent_findings,
        score_change=score_change,
    )
