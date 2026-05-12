"""
MASVS Audit Copilot — Dynamic Scan Orchestrator (Celery Task)
Coordinates the full dynamic analysis pipeline:
    1. Validate scan state
    2. Start dynamic analysis on MobSF
    3. Wait for emulator interaction (90s)
    4. Stop analysis & collect data
    5. Parse dynamic findings + Frida logs
    6. Insert findings into DB
    7. Update scan status

This task is completely isolated from the static scan_orchestrator.
It must be triggered manually — it is NOT connected to any API endpoint.
"""

import logging
import time
import traceback

from app.tasks.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.models import Scan, Finding, Severity, FindingStatus, TriageResult

from app.tasks.mobsf_dynamic_client import (
    start_dynamic_analysis,
    stop_dynamic_analysis,
    get_dynamic_report,
    get_frida_logs,
)
from app.tasks.dynamic_findings_parser import parse_dynamic_findings

logger = logging.getLogger(__name__)


# ─── Noise domains to auto-exclude from scoring ───

NOISE_DOMAINS = [
    "connectivitycheck.gstatic.com",
    "google.com/gen_204",
    "clients3.google.com",
    "detectportal.firefox.com",
]


def _is_noise_domain(finding_dict: dict) -> bool:
    """Return True if the finding's title or description contains a noise domain."""
    text = (finding_dict.get("title", "") + " " + finding_dict.get("description", "")).lower()
    return any(domain.lower() in text for domain in NOISE_DOMAINS)


# ─── Severity string → enum mapping ───

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@celery_app.task(
    bind=True,
    name="dynamic_scan_orchestrator",
    max_retries=2,
    default_retry_delay=60,
)
def dynamic_scan_orchestrator(self, scan_id: int):
    """
    Celery task — full dynamic analysis pipeline.

    Prerequisites:
        - Scan must have scan_mode == "dynamic"
        - Scan must have dynamic_status == "queued"
        - Static scan should be completed (mobsf_scan_hash populated)
        - AVD / emulator must be running at host.docker.internal:5555

    Args:
        scan_id: Database ID of the scan to run dynamic analysis on.

    Returns:
        Dict with scan_id, status, and findings_count.
    """
    db = SessionLocal()

    try:
        # ── Step 1: Load scan and validate state ─────────────────────────
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("dynamic_scan_orchestrator: Scan %d not found", scan_id)
            return {"error": f"Scan {scan_id} not found"}

        if scan.scan_mode != "dynamic":
            logger.warning(
                "Scan %d has scan_mode='%s', expected 'dynamic'",
                scan_id, scan.scan_mode,
            )
            return {"error": f"Scan {scan_id} is not a dynamic scan"}

        if scan.dynamic_status != "queued":
            logger.warning(
                "Scan %d has dynamic_status='%s', expected 'queued'",
                scan_id, scan.dynamic_status,
            )
            return {"error": f"Scan {scan_id} dynamic_status is not 'queued'"}

        # ── Step 2: Mark as running ──────────────────────────────────────
        scan.dynamic_status = "running"
        db.commit()
        logger.info("Scan %d → dynamic_status = running", scan_id)

        # ── Step 3: Get APK hash ─────────────────────────────────────────
        apk_hash = scan.mobsf_scan_hash
        if not apk_hash:
            raise ValueError(
                f"Scan {scan_id} has no mobsf_scan_hash — "
                f"static scan may not have completed"
            )

        logger.info("Scan %d — using mobsf_scan_hash=%s", scan_id, apk_hash)

        # ── Step 4: Start dynamic analysis ───────────────────────────────
        start_result = start_dynamic_analysis(apk_hash)
        logger.info("Scan %d — dynamic analysis started: %s", scan_id, start_result)

        # ── Step 5: Wait for emulator interaction ────────────────────────
        logger.info("Scan %d — waiting 90s for dynamic analysis to run…", scan_id)
        time.sleep(90)

        # ── Step 6: Stop dynamic analysis ────────────────────────────────
        stop_result = stop_dynamic_analysis(apk_hash)
        logger.info("Scan %d — dynamic analysis stopped: %s", scan_id, stop_result)

        # ── Step 7: Get dynamic report ───────────────────────────────────
        report = get_dynamic_report(apk_hash)
        logger.info("Scan %d — dynamic report retrieved", scan_id)

        # ── Step 8: Parse dynamic findings ───────────────────────────────
        parsed = parse_dynamic_findings(scan_id, report)
        logger.info("Scan %d — parsed %d dynamic findings", scan_id, len(parsed))

        # ── Step 9: Insert valid findings into DB ────────────────────────
        findings_count = 0
        for finding_dict in parsed:
            severity_str = finding_dict.get("severity", "info")
            severity_enum = _SEVERITY_MAP.get(severity_str, Severity.INFO)

            # Auto-exclude network noise domains
            is_noise = _is_noise_domain(finding_dict)

            finding = Finding(
                scan_id=scan_id,
                title=finding_dict["title"][:500],
                description=finding_dict.get("description", ""),
                severity=severity_enum,
                status=FindingStatus.FALSE_POSITIVE if is_noise else FindingStatus.OPEN,
                masvs_category=_extract_category(finding_dict.get("masvs_control", "")),
                masvs_control=finding_dict.get("masvs_control", ""),
                triage_result=TriageResult.FALSE_POSITIVE if is_noise else TriageResult.NOT_TRIAGED,
                source=finding_dict.get("source", "dynamic"),
                mapping_confidence=0.85 if finding_dict.get("masvs_control") else 0.0,
                estimated_effort_hours=_effort_hours(severity_str),
                priority_label=_priority_label(severity_str),
            )
            db.add(finding)
            findings_count += 1
            if is_noise:
                logger.info("Scan %d — auto-excluded noise finding: %s", scan_id, finding_dict["title"][:120])

        db.commit()
        logger.info("Scan %d — inserted %d findings", scan_id, findings_count)

        # ── Step 10: Frida logs ──────────────────────────────────────────
        frida_data = get_frida_logs(apk_hash)
        frida_findings_count = 0

        if frida_data is not None:
            # Parse Frida logs as a supplementary report section
            frida_parsed = parse_dynamic_findings(scan_id, {"frida_logs": frida_data})
            for finding_dict in frida_parsed:
                severity_str = finding_dict.get("severity", "info")
                severity_enum = _SEVERITY_MAP.get(severity_str, Severity.INFO)

                # Auto-exclude network noise domains (frida findings too)
                is_noise = _is_noise_domain(finding_dict)

                finding = Finding(
                    scan_id=scan_id,
                    title=finding_dict["title"][:500],
                    description=finding_dict.get("description", ""),
                    severity=severity_enum,
                    status=FindingStatus.FALSE_POSITIVE if is_noise else FindingStatus.OPEN,
                    masvs_category=_extract_category(finding_dict.get("masvs_control", "")),
                    masvs_control=finding_dict.get("masvs_control", ""),
                    triage_result=TriageResult.FALSE_POSITIVE if is_noise else TriageResult.NOT_TRIAGED,
                    source=finding_dict.get("source", "frida"),
                    mapping_confidence=0.85 if finding_dict.get("masvs_control") else 0.0,
                    estimated_effort_hours=_effort_hours(severity_str),
                    priority_label=_priority_label(severity_str),
                )
                db.add(finding)
                frida_findings_count += 1
                if is_noise:
                    logger.info("Scan %d — auto-excluded noise Frida finding: %s", scan_id, finding_dict["title"][:120])

            db.commit()
            logger.info(
                "Scan %d — inserted %d Frida findings", scan_id, frida_findings_count,
            )
        else:
            logger.info("Scan %d — no Frida logs available", scan_id)

        # ── Step 11: Mark as completed ───────────────────────────────────
        scan.dynamic_status = "completed"
        scan.dynamic_error = None
        db.commit()
        logger.info("Scan %d → dynamic_status = completed", scan_id)

        # ── Step 12: Recalculate global score (static + dynamic, TP only) ─
        try:
            from app.mapping.cvss_scorer import calculate_global_score, calculate_grade, ScoredFinding
            from app.mapping.masvs_mapper import MappedFinding
            from app.utils.finding_utils import deduplicate_findings

            tp_findings = db.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.triage_result == TriageResult.TRUE_POSITIVE,
            ).all()
            tp_findings = deduplicate_findings(tp_findings)

            mock_scored = [
                ScoredFinding(
                    finding=MappedFinding(
                        title=f.title, description=f.description or "",
                        severity=f.severity.value, masvs_category=f.masvs_category or "",
                        masvs_control=f.masvs_control or "",
                    ),
                    cvss_vector=f.cvss_vector or "", cvss_score=f.cvss_score or 0,
                ) for f in tp_findings
            ]
            new_score = calculate_global_score(mock_scored)
            new_grade = calculate_grade(new_score)

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.score = new_score
                scan.grade = new_grade
                db.commit()
            logger.info(
                "Scan %d — recalculated score after dynamic: %.1f (%s)",
                scan_id, new_score, new_grade,
            )
        except Exception as e:
            logger.error("Scan %d — score recalculation failed: %s", scan_id, e)

        total = findings_count + frida_findings_count
        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": total,
        }

    except Exception as exc:
        logger.error(
            "dynamic_scan_orchestrator failed for scan %d: %s\n%s",
            scan_id, exc, traceback.format_exc(),
        )
        # Mark scan as failed with truncated error
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.dynamic_status = "failed"
                scan.dynamic_error = str(exc)[:1000]
                db.commit()
        except Exception:
            logger.error("Failed to update scan %d status to failed", scan_id)

        raise self.retry(exc=exc)

    finally:
        db.close()


def _extract_category(masvs_control: str) -> str:
    """
    Extract the MASVS category from a control ID.

    Example: 'MASVS-NETWORK-1' → 'MASVS-NETWORK'
             'MASVS-CRYPTO-1'  → 'MASVS-CRYPTO'
    """
    if not masvs_control:
        return ""
    parts = masvs_control.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return masvs_control


def _effort_hours(severity: str) -> float:
    return {
        "critical": 4.0,
        "high": 8.0,
        "medium": 16.0,
        "low": 32.0,
        "info": 0.0,
    }.get((severity or "info").lower(), 0.0)


def _priority_label(severity: str) -> str:
    return {
        "critical": "P0",
        "high": "P1",
        "medium": "P1",
        "low": "P2",
        "info": "P3",
    }.get((severity or "info").lower(), "P3")
