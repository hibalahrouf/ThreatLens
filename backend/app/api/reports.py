"""
MASVS Audit Copilot — Reports API Routes
POST /api/reports/{scan_id}/pdf        Generate PDF report
POST /api/reports/{scan_id}/markdown   Generate Markdown report
POST /api/reports/{scan_id}/sarif      Generate SARIF report
GET  /api/reports/{scan_id}/           List reports for a scan
GET  /api/reports/{scan_id}/{report_id}/download  Download a report
"""

import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.storage import storage_client
from app.models.models import User, Scan, Finding, Report, Project, ReportFormat, ScanStatus
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_user_scan(db: Session, scan_id: int, user_id: int) -> Scan:
    """Get a scan ensuring it belongs to the user."""
    scan = (
        db.query(Scan).join(Project)
        .filter(Scan.id == scan_id, Project.user_id == user_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.DONE:
        raise HTTPException(status_code=400, detail="Scan is not complete yet")
    return scan


def _get_findings_dicts(db: Session, scan_id: int) -> list:
    """Get findings as dictionaries for report generators."""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    result = []
    for f in findings:
        result.append({
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
            "masvs_category": f.masvs_category,
            "masvs_control": f.masvs_control,
            "mastg_test": f.mastg_test,
            "cvss_vector": f.cvss_vector,
            "cvss_score": f.cvss_score,
            "fingerprint": f.fingerprint,
            "affected_file": f.affected_file,
            "affected_code": f.affected_code,
            "line_number": f.line_number,
            "triage_result": f.triage_result.value if hasattr(f.triage_result, 'value') else f.triage_result,
            "triage_justification": f.triage_justification,
            "remediation_description": f.remediation_description,
            "remediation_code": f.remediation_code,
            "estimated_effort_hours": f.estimated_effort_hours,
            "priority_label": f.priority_label,
            "source": f.source,
            "mapping_confidence": f.mapping_confidence,
            "semantic_group_id": f.semantic_group_id,
            "root_cause": f.root_cause,
            "status": f.status.value if hasattr(f.status, 'value') else f.status,
        })
    return result


def _get_scan_data(scan: Scan) -> dict:
    """Convert scan to a data dict for report generators."""
    return {
        "id": scan.id,
        "file_name": scan.file_name,
        "file_hash": scan.file_hash or "N/A",
        "app_version": scan.app_version,
        "score": scan.score or 0,
        "grade": scan.grade or "?",
        "executive_summary": getattr(scan, 'executive_summary', None),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scan_mode": getattr(scan, "scan_mode", "static"),
        "dynamic_status": getattr(scan, "dynamic_status", "not_requested"),
        "dynamic_error": getattr(scan, "dynamic_error", None),
    }


def _render_diff_report_html(
    base_scan: Scan,
    compare_scan: Scan,
    new_findings: list,
    fixed_findings: list,
    persistent_findings: list,
    score_change: float | None,
) -> str:
    def rows(findings: list) -> str:
        if not findings:
            return "<tr><td colspan='4'>None</td></tr>"
        return "".join(
            "<tr>"
            f"<td>{f.severity.value if hasattr(f.severity, 'value') else f.severity}</td>"
            f"<td>{f.masvs_control or 'N/A'}</td>"
            f"<td>{f.title}</td>"
            f"<td>{f.cvss_score if f.cvss_score is not None else 'N/A'}</td>"
            "</tr>"
            for f in findings
        )

    delta = "N/A" if score_change is None else f"{score_change:+.1f}"
    return f"""
    <!doctype html>
    <html><head><meta charset="utf-8"><style>
      body {{ font-family: sans-serif; color: #172033; padding: 28px; }}
      h1 {{ margin-bottom: 4px; }}
      .muted {{ color: #64748b; }}
      .cards {{ display: flex; gap: 16px; margin: 24px 0; }}
      .card {{ flex: 1; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; }}
      .score {{ font-size: 28px; font-weight: 700; }}
      table {{ width: 100%; border-collapse: collapse; margin: 12px 0 24px; }}
      th, td {{ border: 1px solid #e2e8f0; padding: 8px; font-size: 12px; text-align: left; }}
      th {{ background: #f8fafc; }}
    </style></head>
    <body>
      <h1>Security Delta Report</h1>
      <p class="muted">Scan #{base_scan.id} compared with Scan #{compare_scan.id}</p>
      <div class="cards">
        <div class="card"><strong>Baseline</strong><div>{base_scan.file_name}</div><div class="score">{base_scan.score or 0:.1f}</div></div>
        <div class="card"><strong>Compared</strong><div>{compare_scan.file_name}</div><div class="score">{compare_scan.score or 0:.1f}</div><div>Delta: {delta}</div></div>
      </div>
      <h2>New Findings ({len(new_findings)})</h2>
      <table><tr><th>Severity</th><th>MASVS</th><th>Finding</th><th>CVSS</th></tr>{rows(new_findings)}</table>
      <h2>Fixed Findings ({len(fixed_findings)})</h2>
      <table><tr><th>Severity</th><th>MASVS</th><th>Finding</th><th>CVSS</th></tr>{rows(fixed_findings)}</table>
      <h2>Persistent Findings ({len(persistent_findings)})</h2>
      <table><tr><th>Severity</th><th>MASVS</th><th>Finding</th><th>CVSS</th></tr>{rows(persistent_findings)}</table>
    </body></html>
    """


@router.post("/{scan_id}/pdf", status_code=status.HTTP_201_CREATED)
async def generate_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a PDF audit report for a completed scan."""
    scan = _get_user_scan(db, scan_id, current_user.id)
    findings = _get_findings_dicts(db, scan_id)
    scan_data = _get_scan_data(scan)

    from app.reports.pdf_generator import generate_pdf_report

    # Generate to temp file, then upload to MinIO
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        generate_pdf_report(scan_data, findings, tmp_path)

        # Upload to MinIO
        with open(tmp_path, "rb") as f:
            pdf_bytes = f.read()

        object_name = f"reports/{scan_id}/audit_report.pdf"
        storage_client.upload_file(pdf_bytes, object_name, "application/pdf")

        # Save report record
        report = Report(
            scan_id=scan_id,
            format=ReportFormat.PDF,
            file_path=object_name,
            file_size=len(pdf_bytes),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        return {
            "report_id": report.id,
            "format": "pdf",
            "file_size": len(pdf_bytes),
            "download_url": f"/api/reports/{scan_id}/{report.id}/download",
        }
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.post("/{scan_id}/markdown", status_code=status.HTTP_201_CREATED)
async def generate_markdown(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a Markdown audit report for a completed scan."""
    scan = _get_user_scan(db, scan_id, current_user.id)
    findings = _get_findings_dicts(db, scan_id)
    scan_data = _get_scan_data(scan)

    from app.reports.markdown_exporter import generate_markdown_report

    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    try:
        generate_markdown_report(scan_data, findings, tmp_path)

        with open(tmp_path, "rb") as f:
            md_bytes = f.read()

        object_name = f"reports/{scan_id}/audit_report.md"
        storage_client.upload_file(md_bytes, object_name, "text/markdown")

        report = Report(
            scan_id=scan_id,
            format=ReportFormat.MARKDOWN,
            file_path=object_name,
            file_size=len(md_bytes),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        return {
            "report_id": report.id,
            "format": "markdown",
            "file_size": len(md_bytes),
            "download_url": f"/api/reports/{scan_id}/{report.id}/download",
        }
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.post("/{scan_id}/sarif", status_code=status.HTTP_201_CREATED)
async def generate_sarif(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a SARIF 2.1 report for CI/CD integration."""
    scan = _get_user_scan(db, scan_id, current_user.id)
    findings = _get_findings_dicts(db, scan_id)
    scan_data = _get_scan_data(scan)

    from app.reports.sarif_exporter import generate_sarif_report

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        generate_sarif_report(scan_data, findings, tmp_path)

        with open(tmp_path, "rb") as f:
            sarif_bytes = f.read()

        object_name = f"reports/{scan_id}/audit_report.sarif"
        storage_client.upload_file(sarif_bytes, object_name, "application/json")

        report = Report(
            scan_id=scan_id,
            format=ReportFormat.SARIF,
            file_path=object_name,
            file_size=len(sarif_bytes),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        return {
            "report_id": report.id,
            "format": "sarif",
            "file_size": len(sarif_bytes),
            "download_url": f"/api/reports/{scan_id}/{report.id}/download",
        }
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.post("/diff/{base_scan_id}/{compare_scan_id}/pdf", status_code=status.HTTP_201_CREATED)
async def generate_diff_pdf(
    base_scan_id: int,
    compare_scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a side-by-side PDF report comparing two completed scans."""
    base_scan = _get_user_scan(db, base_scan_id, current_user.id)
    compare_scan = _get_user_scan(db, compare_scan_id, current_user.id)

    base_findings = db.query(Finding).filter(Finding.scan_id == base_scan_id).all()
    compare_findings = db.query(Finding).filter(Finding.scan_id == compare_scan_id).all()
    base_by_fp = {f.fingerprint: f for f in base_findings if f.fingerprint}
    compare_by_fp = {f.fingerprint: f for f in compare_findings if f.fingerprint}
    base_fps = set(base_by_fp)
    compare_fps = set(compare_by_fp)

    new_findings = [compare_by_fp[fp] for fp in sorted(compare_fps - base_fps)]
    fixed_findings = [base_by_fp[fp] for fp in sorted(base_fps - compare_fps)]
    persistent_findings = [compare_by_fp[fp] for fp in sorted(base_fps & compare_fps)]
    score_change = None
    if base_scan.score is not None and compare_scan.score is not None:
        score_change = compare_scan.score - base_scan.score

    html = _render_diff_report_html(
        base_scan,
        compare_scan,
        new_findings,
        fixed_findings,
        persistent_findings,
        score_change,
    )

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(tmp_path)
        with open(tmp_path, "rb") as f:
            pdf_bytes = f.read()

        object_name = f"reports/{compare_scan_id}/diff_report_{base_scan_id}_{compare_scan_id}.pdf"
        storage_client.upload_file(pdf_bytes, object_name, "application/pdf")
        report = Report(
            scan_id=compare_scan_id,
            format=ReportFormat.PDF,
            file_path=object_name,
            file_size=len(pdf_bytes),
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return {
            "report_id": report.id,
            "format": "pdf",
            "file_size": len(pdf_bytes),
            "download_url": f"/api/reports/{compare_scan_id}/{report.id}/download",
        }
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.get("/{scan_id}/")
async def list_reports(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all generated reports for a scan."""
    _get_user_scan(db, scan_id, current_user.id)

    reports = db.query(Report).filter(Report.scan_id == scan_id).order_by(Report.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "format": r.format.value if hasattr(r.format, 'value') else r.format,
            "file_size": r.file_size,
            "created_at": r.created_at.isoformat(),
            "download_url": f"/api/reports/{scan_id}/{r.id}/download",
        }
        for r in reports
    ]


@router.get("/{scan_id}/{report_id}/download")
async def download_report(
    scan_id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a generated report file."""
    _get_user_scan(db, scan_id, current_user.id)

    report = db.query(Report).filter(Report.id == report_id, Report.scan_id == scan_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Download from MinIO to temp file
    file_data = storage_client.download_file(report.file_path)

    content_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.MARKDOWN: "text/markdown",
        ReportFormat.SARIF: "application/json",
    }
    extensions = {
        ReportFormat.PDF: ".pdf",
        ReportFormat.MARKDOWN: ".md",
        ReportFormat.SARIF: ".sarif",
    }

    fmt = report.format
    ext = extensions.get(fmt, ".bin")
    content_type = content_types.get(fmt, "application/octet-stream")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(file_data)
        tmp_path = tmp.name

    return FileResponse(
        path=tmp_path,
        media_type=content_type,
        filename=f"audit_report_{scan_id}{ext}",
    )
