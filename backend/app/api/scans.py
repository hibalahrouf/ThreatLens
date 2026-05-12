"""
MASVS Audit Copilot — Scan API Routes
POST   /api/scans/upload          Upload an APK/IPA and start a scan
GET    /api/scans/                List all scans for the current user
GET    /api/scans/{scan_id}       Get scan details
GET    /api/scans/{scan_id}/findings  Get findings for a scan
WS     /api/scans/{scan_id}/ws    WebSocket for real-time progress
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.core.storage import storage_client
from app.core.config import settings
from app.models.models import User, Project, Scan, Finding, Report, AttackPath, ScanStatus
from app.models.schemas import (
    ScanUploadResponse,
    ScanResponse,
    ScanListResponse,
    FindingResponse,
)
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])

# ─── Allowed file extensions ───
ALLOWED_EXTENSIONS = {".apk", ".ipa", ".xapk", ".aab"}


def validate_file_extension(filename: str) -> str:
    """Validate and return the file extension."""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )
    return ext


@router.post("/upload", response_model=ScanUploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_scan(
    file: UploadFile = File(..., description="APK or IPA file to scan"),
    project_name: str = Form(..., description="Project name"),
    app_version: Optional[str] = Form(None, description="App version (e.g., 1.2.3)"),
    scan_mode: str = Form(default="static", description="Scan mode: 'static' or 'dynamic'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload a mobile application file and start a security scan.

    The scan runs asynchronously via Celery. Use the WebSocket endpoint
    or GET /api/scans/{scan_id} to track progress.

    Parameters:
        scan_mode: "static" (default) runs SAST only.
                   "dynamic" queues dynamic analysis after static scan.
    """
    # ─── Validate scan_mode ───
    if scan_mode not in ("static", "dynamic"):
        raise HTTPException(
            status_code=422,
            detail="scan_mode must be 'static' or 'dynamic'",
        )

    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    ext = validate_file_extension(file.filename)

    # Read file content
    file_data = await file.read()
    if len(file_data) == 0:
        raise HTTPException(status_code=400, detail="File is empty")
    if len(file_data) > 500 * 1024 * 1024:  # 500 MB max
        raise HTTPException(status_code=400, detail="File exceeds 500 MB limit")

    # Compute file hash
    file_hash = storage_client.compute_sha256(file_data)

    # Get or create project
    project = (
        db.query(Project)
        .filter(Project.name == project_name, Project.user_id == current_user.id)
        .first()
    )
    if not project:
        platform = "android" if ext in {".apk", ".xapk", ".aab"} else "ios"
        project = Project(
            name=project_name,
            user_id=current_user.id,
            platform=platform,
        )
        db.add(project)
        db.commit()
        db.refresh(project)

    # ─── Determine dynamic_status based on scan_mode ───
    dynamic_status = "queued" if scan_mode == "dynamic" else "not_requested"

    # Create scan record
    scan = Scan(
        project_id=project.id,
        file_name=file.filename,
        file_path="",  # Will be set after MinIO upload
        file_hash=file_hash,
        app_version=app_version,
        status=ScanStatus.UPLOADING,
        progress=0,
        scan_mode=scan_mode,
        dynamic_status=dynamic_status,
        dynamic_error=None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Upload to MinIO
    object_name = f"scans/{scan.id}/{file.filename}"
    try:
        storage_client.upload_file(
            file_data=file_data,
            object_name=object_name,
            content_type=file.content_type or "application/octet-stream",
        )
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = f"Failed to upload to storage: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to upload file to storage")

    # Update scan with storage path
    scan.file_path = object_name
    scan.status = ScanStatus.PENDING
    scan.progress = 5
    db.commit()

    # ─── Dispatch static analysis pipeline (always runs) ───
    from app.tasks.scan_tasks import scan_orchestrator

    scan_orchestrator.delay(scan.id)

    # Dynamic pipeline is triggered automatically by scan_orchestrator
    # after static analysis completes successfully.

    return ScanUploadResponse(
        job_id=scan.id,
        scan_id=scan.id,
        file_name=file.filename,
        status=ScanStatus.PENDING.value,
        message=f"Scan queued successfully (mode={scan_mode}). Track progress at /api/scans/{scan.id}/ws",
    )


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all scans for the authenticated user with pagination.
    """
    query = (
        db.query(Scan)
        .join(Project)
        .filter(Project.user_id == current_user.id)
    )

    if status_filter:
        query = query.filter(Scan.status == status_filter)

    total = query.count()
    scans = (
        query
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    scan_responses = []
    for scan in scans:
        findings_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == scan.id).scalar()
        resp = ScanResponse.model_validate(scan)
        resp.findings_count = findings_count
        scan_responses.append(resp)

    return ScanListResponse(
        scans=scan_responses,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get the full details of a specific scan.
    """
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == scan.id).scalar()
    resp = ScanResponse.model_validate(scan)
    resp.findings_count = findings_count
    return resp


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
async def get_scan_findings(
    scan_id: int,
    severity: Optional[str] = Query(None),
    masvs_category: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get all findings for a specific scan, with optional filters.
    """
    # Verify scan belongs to user
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if masvs_category:
        query = query.filter(Finding.masvs_category == masvs_category)
    if status_filter:
        query = query.filter(Finding.status == status_filter)

    findings = query.order_by(Finding.cvss_score.desc().nullslast()).all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/{scan_id}/attack-paths")
async def get_scan_attack_paths(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get stored chained attack scenarios for a scan."""
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    paths = (
        db.query(AttackPath)
        .filter(AttackPath.scan_id == scan_id)
        .order_by(AttackPath.exploitability_score.desc().nullslast())
        .all()
    )
    return [
        {
            "id": path.id,
            "scan_id": path.scan_id,
            "title": path.title,
            "description": path.description,
            "severity": path.severity.value if hasattr(path.severity, "value") else path.severity,
            "finding_ids": json.loads(path.finding_ids or "[]"),
            "exploitability_score": path.exploitability_score,
            "created_at": path.created_at.isoformat() if path.created_at else None,
        }
        for path in paths
    ]


@router.websocket("/{scan_id}/ws")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: int,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    WebSocket endpoint for real-time scan progress updates.

    The client connects and receives JSON messages with:
    - scan_id, status, progress (0-100), current_step, message
    
    Connection closes automatically when the scan is done or failed.
    """
    import asyncio
    import jwt as pyjwt

    try:
        if not token:
            await websocket.close(code=1008)
            return
        payload = pyjwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            await websocket.close(code=1008)
            return
        user_id = int(payload.get("sub"))
        owned_scan = (
            db.query(Scan)
            .join(Project)
            .filter(Scan.id == scan_id, Project.user_id == user_id)
            .first()
        )
        if not owned_scan:
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        while True:
            # Poll the scan status from DB
            db.expire_all()  # Force fresh read
            scan = db.query(Scan).filter(Scan.id == scan_id).first()

            if not scan:
                await websocket.send_json({
                    "error": "Scan not found",
                    "scan_id": scan_id,
                })
                break

            progress_data = {
                "scan_id": scan.id,
                "status": scan.status.value if hasattr(scan.status, 'value') else scan.status,
                "progress": scan.progress or 0,
                "current_step": _status_to_step(scan.status),
                "message": scan.error_message if scan.status == ScanStatus.FAILED else None,
                "score": scan.score,
                "grade": scan.grade,
            }
            await websocket.send_json(progress_data)

            # Stop polling when scan is terminal
            if scan.status in (ScanStatus.DONE, ScanStatus.FAILED):
                break

            await asyncio.sleep(2)  # Poll every 2 seconds

    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


def _status_to_step(status: ScanStatus) -> str:
    """Convert scan status to human-readable step description."""
    return {
        ScanStatus.PENDING: "Waiting in queue...",
        ScanStatus.UPLOADING: "Uploading to analysis engine...",
        ScanStatus.RUNNING: "Running static analysis (MobSF)...",
        ScanStatus.ANALYZING: "Mapping findings to MASVS controls...",
        ScanStatus.GENERATING_REPORT: "Generating audit report...",
        ScanStatus.DONE: "Scan complete ✓",
        ScanStatus.FAILED: "Scan failed ✗",
    }.get(status, "Processing...")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Cancel a running or pending scan.
    Sets the scan status to FAILED with an appropriate message.
    """
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cancellable = {ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING, ScanStatus.UPLOADING, ScanStatus.GENERATING_REPORT}
    if scan.status not in cancellable:
        raise HTTPException(
            status_code=400,
            detail=f"Scan cannot be cancelled in '{scan.status.value}' state",
        )

    scan.status = ScanStatus.FAILED
    scan.error_message = "Cancelled by user"
    db.commit()

    return {"message": f"Scan {scan_id} cancelled successfully"}


@router.delete("/")
async def delete_all_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete ALL scans for the current user.
    """
    scans = (
        db.query(Scan)
        .join(Project)
        .filter(Project.user_id == current_user.id)
        .all()
    )
    count = len(scans)
    
    for scan in scans:
        if scan.file_path:
            storage_client.delete_file(scan.file_path)
            
        # Optional: delete report files
        reports = db.query(Report).filter(Report.scan_id == scan.id).all()
        for r in reports:
            if r.file_path:
                storage_client.delete_file(r.file_path)
                
        db.delete(scan)

    db.commit()
    return {"message": f"Successfully deleted {count} scans"}


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a specific scan.
    """
    scan = (
        db.query(Scan)
        .join(Project)
        .filter(Scan.id == scan_id, Project.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.file_path:
        storage_client.delete_file(scan.file_path)
        
    reports = db.query(Report).filter(Report.scan_id == scan.id).all()
    for r in reports:
        if r.file_path:
            storage_client.delete_file(r.file_path)
            
    db.delete(scan)
    db.commit()
    
    return {"message": f"Scan {scan_id} deleted successfully"}
