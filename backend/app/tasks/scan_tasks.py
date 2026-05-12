"""
MASVS Audit Copilot — Celery Scan Orchestrator Task
Coordinates the full scan pipeline: MobSF → MASVS Mapping → CVSS → SBOM → LLM → Report.
"""

import traceback
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.models import Scan, Finding, ScanStatus, Severity, FindingStatus, TriageResult


_EFFORT_HOURS = {
    "critical": 4.0,
    "high": 8.0,
    "medium": 16.0,
    "low": 32.0,
    "info": 0.0,
}

_PRIORITY_LABELS = {
    "critical": "P0",
    "high": "P1",
    "medium": "P1",
    "low": "P2",
    "info": "P3",
}


def _update_scan(db, scan_id: int, **kwargs):
    """Helper to update scan fields in the database."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        for key, value in kwargs.items():
            setattr(scan, key, value)
        db.commit()
    return scan


def _historical_feedback_text(db, feedback_model, finding: Finding) -> str:
    """Return compact auditor feedback examples for similar findings."""
    if not finding.masvs_control:
        return ""
    rows = (
        db.query(feedback_model)
        .filter(feedback_model.masvs_control == finding.masvs_control)
        .order_by(feedback_model.created_at.desc())
        .limit(3)
        .all()
    )
    if not rows:
        return ""
    return "\n".join(
        f"- '{row.finding_title}' was marked {row.corrected_status}: {row.auditor_reason or 'No reason provided'}"
        for row in rows
    )


def _send_scan_notification(file_name: str, score: float, grade: str, findings: list[Finding]) -> None:
    """Post a compact scan summary to configured Slack or Teams webhooks."""
    try:
        from app.core.config import settings
        import httpx

        webhook = settings.SLACK_WEBHOOK_URL or settings.TEAMS_WEBHOOK_URL
        if not webhook:
            return
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        text = (
            f"MASVS scan complete for {file_name}: {score:.1f}/100 ({grade}). "
            f"Findings: {len(findings)} | Critical: {critical} | High: {high}"
        )
        httpx.post(webhook, json={"text": text}, timeout=10)
    except Exception:
        return


def _create_jira_issues(findings: list[Finding]) -> None:
    """Create Jira issues for confirmed critical/high findings when configured."""
    try:
        from app.engines.jira_client import create_issue_for_finding
        for finding in findings:
            if finding.jira_issue_key:
                continue
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                issue_key = create_issue_for_finding(finding)
                if issue_key:
                    finding.jira_issue_key = issue_key
    except Exception:
        return


@celery_app.task(
    bind=True,
    name="scan_orchestrator",
    max_retries=2,
    default_retry_delay=30,
)
def scan_orchestrator(self, scan_id: int):
    """
    Main scan pipeline — orchestrates all engines sequentially:
    1. Download APK from MinIO
    2. MobSF static analysis
    3. MASVS mapping
    4. CVSS scoring
    5. Fingerprint generation
    6. SBOM & CVE lookup
    7. LLM triage
    8. LLM remediation
    9. Global scoring
    """
    db = SessionLocal()

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        # ── Step 1: Mark as running ──
        _update_scan(db, scan_id,
                      status=ScanStatus.RUNNING, progress=10,
                      started_at=datetime.now(timezone.utc))

        # ── Step 2: Download from MinIO ──
        _update_scan(db, scan_id, progress=15)
        from app.core.storage import storage_client
        try:
            file_data = storage_client.download_file(scan.file_path)
        except Exception as e:
            _update_scan(db, scan_id, status=ScanStatus.FAILED,
                          error_message=f"Storage download failed: {e}")
            return {"error": str(e)}

        # ── Step 3: MobSF static analysis ──
        _update_scan(db, scan_id, progress=20)
        mobsf_report = {}
        mobsf = None       # kept in outer scope so later steps can call it safely
        mobsf_hash = ""    # md5 returned by MobSF upload
        try:
            from app.engines.mobsf_client import MobSFClient
            mobsf = MobSFClient()
            mobsf_report = mobsf.scan_and_wait(file_data, scan.file_name)
            mobsf_hash = mobsf_report.get("md5", "")
            _update_scan(db, scan_id, progress=40,
                          mobsf_scan_hash=mobsf_hash)
        except Exception as e:
            # MobSF might not be available — continue with empty report
            _update_scan(db, scan_id, progress=40,
                          error_message=f"MobSF unavailable: {e}")

        # ── Step 4: Map findings to MASVS ──
        _update_scan(db, scan_id, status=ScanStatus.ANALYZING, progress=50)
        from app.mapping.masvs_mapper import map_findings
        mapped_findings = map_findings(mobsf_report)

        # ── Step 5: CVSS scoring ──
        _update_scan(db, scan_id, progress=55)
        from app.mapping.cvss_scorer import score_findings
        scored_findings = score_findings(mapped_findings)

        # ── Step 6: Generate fingerprints ──
        _update_scan(db, scan_id, progress=60)
        from app.mapping.fingerprint import generate_fingerprint

        # ── Step 7: SBOM analysis ──
        _update_scan(db, scan_id, progress=65)
        sbom_findings = []
        try:
            from app.engines.sbom import extract_dependencies_from_apk, check_osv_vulnerabilities
            deps = extract_dependencies_from_apk(file_data)
            vuln_deps = check_osv_vulnerabilities(deps)
            for vd in vuln_deps:
                from app.mapping.masvs_mapper import MappedFinding
                sbom_findings.append(MappedFinding(
                    title=f"Vulnerable dependency: {vd.dependency.name}",
                    description=f"{vd.summary}. CVEs: {', '.join(vd.cve_ids)}. "
                                f"Fix: upgrade to {vd.fixed_version or 'latest'}.",
                    severity=vd.severity,
                    masvs_category="MASVS-CODE",
                    masvs_control="MASVS-CODE-3",
                    source="sbom",
                ))
        except Exception:
            pass

        # Score SBOM findings too
        all_scored = scored_findings + score_findings(sbom_findings)

        # ── Step 8: Save findings to database ──
        _update_scan(db, scan_id, progress=70)
        severity_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }

        for sf in all_scored:
            fp = generate_fingerprint(sf.finding)
            finding = Finding(
                scan_id=scan_id,
                title=sf.finding.title[:500],
                description=sf.finding.description,
                severity=severity_map.get(sf.finding.severity, Severity.INFO),
                status=FindingStatus.OPEN,
                masvs_category=sf.finding.masvs_category,
                masvs_control=sf.finding.masvs_control,
                mastg_test=sf.finding.mastg_test,
                cvss_vector=sf.cvss_vector,
                cvss_score=sf.cvss_score,
                fingerprint=fp,
                affected_file=sf.finding.affected_file,
                affected_code=sf.finding.affected_code,
                line_number=sf.finding.line_number,
                triage_result=TriageResult.NOT_TRIAGED,
                source=sf.finding.source,
                mapping_confidence=0.95 if sf.finding.masvs_control else 0.0,
                estimated_effort_hours=_EFFORT_HOURS.get(sf.finding.severity, 0.0),
                priority_label=_PRIORITY_LABELS.get(sf.finding.severity, "P3"),
            )
            db.add(finding)
        db.commit()

        # ── Step 9: LLM Triage ──
        _update_scan(db, scan_id, status=ScanStatus.ANALYZING, progress=73)
        try:
            from app.engines.llm_dedup import group_findings_by_root_cause
            db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            for group in group_findings_by_root_cause(db_findings):
                for finding_id in group.finding_ids:
                    f = db.query(Finding).filter(Finding.id == finding_id).first()
                    if f:
                        f.semantic_group_id = group.group_id
                        f.root_cause = group.root_cause
            db.commit()
        except Exception as e:
            _update_scan(db, scan_id, error_message=f"Semantic grouping skipped: {e}")

        _update_scan(db, scan_id, status=ScanStatus.ANALYZING, progress=75)
        try:
            from app.engines.llm_triage import triage_findings_batch
            from app.models.models import AuditorFeedback
            db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            findings_dicts = [
                {
                    "id": f.id, "title": f.title, "severity": f.severity.value,
                    "masvs_control": f.masvs_control, "description": f.description,
                    "affected_file": f.affected_file, "affected_code": f.affected_code,
                    "historical_feedback": _historical_feedback_text(db, AuditorFeedback, f),
                } for f in db_findings
            ]

            # Enrich only ambiguous findings with decompiled source from MobSF.
            # Rule-confirmed findings bypass the LLM entirely, so fetching their
            # source is wasted I/O — we gate each HTTP call behind pre-triage.
            if mobsf is not None and mobsf_hash:
                from app.engines.llm_triage import rule_based_pre_triage
                for fd in findings_dicts:
                    if rule_based_pre_triage(fd) is None:  # only ambiguous findings need source
                        file_path = fd.get("affected_file") or ""
                        if file_path:
                            source = mobsf.get_source_file(mobsf_hash, file_path)
                            if source is not None:
                                fd["code_context"] = source[:1000]

            triage_decisions = triage_findings_batch(findings_dicts)

            for decision in triage_decisions:
                f = db.query(Finding).filter(Finding.id == decision.finding_id).first()
                if f:
                    f.triage_result = TriageResult.TRUE_POSITIVE if decision.is_true_positive else TriageResult.FALSE_POSITIVE
                    f.triage_justification = decision.justification
                    if decision.suggested_severity:
                        f.severity = severity_map.get(decision.suggested_severity, f.severity)
                        f.estimated_effort_hours = _EFFORT_HOURS.get(decision.suggested_severity, f.estimated_effort_hours)
                        f.priority_label = _PRIORITY_LABELS.get(decision.suggested_severity, f.priority_label)
            db.commit()
        except Exception as e:
            _update_scan(db, scan_id, error_message=f"LLM Triage skipped: {e}")

        # ── Step 10: LLM Auto-Remediation ──
        _update_scan(db, scan_id, status=ScanStatus.ANALYZING, progress=85)
        try:
            from app.engines.llm_remediation import generate_remediation
            tp_findings = db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.triage_result == TriageResult.TRUE_POSITIVE
            ).all()

            for f in tp_findings:
                remedy = generate_remediation(
                    finding_id=f.id, title=f.title, severity=f.severity.value,
                    masvs_control=f.masvs_control or "MASVS-GENERIC",
                    description=f.description or "", affected_file=f.affected_file or "",
                    vulnerable_code=f.affected_code or "", language="kotlin" # Default to kotlin for now
                )
                f.remediation_description = remedy.description
                f.remediation_code = remedy.code_patch
            db.commit()
        except Exception as e:
            _update_scan(db, scan_id, error_message=f"LLM Remediation skipped: {e}")

        # ── Step 11: Calculate global score ──
        _update_scan(db, scan_id, status=ScanStatus.GENERATING_REPORT, progress=90)
        from app.mapping.cvss_scorer import calculate_global_score, calculate_grade

        # Bug fix: only score confirmed (true positive) findings — not dismissed ones
        final_findings = db.query(Finding).filter(
            Finding.scan_id == scan_id,
            Finding.triage_result == TriageResult.TRUE_POSITIVE
        ).all()

        # Deduplicate findings so the same vulnerability detected in multiple
        # locations (e.g. StrandHogg on 4 Activities) only counts once.
        from app.utils.finding_utils import deduplicate_findings
        final_findings = deduplicate_findings(final_findings)

        # Build ScoredFinding objects for the scorer
        from app.mapping.masvs_mapper import MappedFinding
        from app.mapping.cvss_scorer import ScoredFinding
        mock_scored = [
            ScoredFinding(
                finding=MappedFinding(
                    title=f.title, description=f.description or "",
                    severity=f.severity.value, masvs_category=f.masvs_category or "",
                    masvs_control=f.masvs_control or "",
                ),
                cvss_vector=f.cvss_vector or "", cvss_score=f.cvss_score or 0,
            ) for f in final_findings
        ]
        score = calculate_global_score(mock_scored)
        grade = calculate_grade(score)

        try:
            from app.reports.report_helpers import generate_executive_summary
            all_summary_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
            summary_payload = [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "masvs_category": f.masvs_category,
                    "cvss_score": f.cvss_score,
                    "triage_result": f.triage_result.value,
                }
                for f in all_summary_findings
            ]
            confirmed = [f for f in summary_payload if f["triage_result"] != "false_positive"]
            dismissed = [f for f in summary_payload if f["triage_result"] == "false_positive"]
            executive_summary = generate_executive_summary(
                {"file_name": scan.file_name, "score": score, "grade": grade},
                confirmed,
                dismissed,
            )
        except Exception:
            executive_summary = None

        try:
            from app.engines.attack_paths import regenerate_attack_paths
            regenerate_attack_paths(db, scan_id)
        except Exception as e:
            _update_scan(db, scan_id, error_message=f"Attack path generation skipped: {e}")

        # ── Done ──
        _update_scan(db, scan_id,
                      status=ScanStatus.DONE, progress=100,
                      score=score, grade=grade,
                      executive_summary=executive_summary,
                      completed_at=datetime.now(timezone.utc))

        _send_scan_notification(scan.file_name, score, grade, final_findings)
        _create_jira_issues(final_findings)
        db.commit()

        # ── Post-static: trigger dynamic analysis if requested ──
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and scan.scan_mode == "dynamic":
            # Preserve static-only score before dynamic findings change it
            scan.static_score = scan.score
            db.commit()
            from app.tasks.dynamic_scan_tasks import dynamic_scan_orchestrator
            dynamic_scan_orchestrator.delay(scan_id)

        return {"scan_id": scan_id, "status": "done", "score": score, "grade": grade}

    except Exception as e:
        _update_scan(db, scan_id, status=ScanStatus.FAILED,
                      error_message=f"{type(e).__name__}: {e}\n{traceback.format_exc()}")
        raise self.retry(exc=e)
    finally:
        db.close()
