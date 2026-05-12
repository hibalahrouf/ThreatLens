"""
One-time script to rerun LLM remediation for true-positive findings in scan 8.
"""

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import SessionLocal
from app.engines.llm_remediation import generate_remediation
from app.models.models import Finding, TriageResult


SCAN_ID = 8


def main() -> None:
    db = SessionLocal()
    try:
        findings = (
            db.query(Finding)
            .filter(
                Finding.scan_id == SCAN_ID,
                Finding.triage_result == TriageResult.TRUE_POSITIVE,
            )
            .all()
        )

        for finding in findings:
            try:
                remedy = generate_remediation(
                    finding_id=finding.id,
                    title=finding.title,
                    severity=finding.severity.value,
                    masvs_control=finding.masvs_control or "MASVS-GENERIC",
                    description=finding.description or "",
                    affected_file=finding.affected_file or "",
                    vulnerable_code=finding.affected_code or "",
                    language="kotlin",
                )
                finding.remediation_description = remedy.description
                finding.remediation_code = remedy.code_patch
                db.commit()

                status = "succeeded" if remedy.code_patch or remedy.description else "failed"
                print(f"{finding.title}: remediation {status}")
            except Exception as exc:
                db.rollback()
                print(f"{finding.title}: remediation failed ({exc})")
    finally:
        db.close()


if __name__ == "__main__":
    main()
