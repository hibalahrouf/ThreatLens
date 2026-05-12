"""
MASVS Audit Copilot — Finding Utilities
Shared deduplication and normalization functions used by both the
scan pipeline (scan_tasks.py) and the report generator (pdf_generator.py).
"""

import re
from typing import List


def normalize_title(title: str) -> str:
    """Normalize a finding title for deduplication.

    Strips Java class names like (com.android.insecurebankv2.DoTransfer)
    so that the same vulnerability detected on different Activities/Services
    shares a single deduplication key.
    """
    cleaned = re.sub(r'\(com\.[a-z0-9.]+\.(\w+)\)', '(APP)', title)
    return cleaned[:80]


def deduplicate_findings(findings: list) -> list:
    """Deduplicate findings by normalized title (or rule_id if available).

    When the same vulnerability appears on multiple components (e.g.
    StrandHogg 2.0 on 4 Activities), only the instance with the highest
    CVSS score is kept.

    Works with both ORM Finding objects and plain dictionaries.
    """
    deduped = {}
    for f in findings:
        # Support both ORM objects (getattr) and dicts (.get)
        if isinstance(f, dict):
            title = f.get("title") or str(f.get("id", ""))
            rule_id = f.get("rule_id")
            cvss = f.get("cvss_score") or 0
        else:
            title = getattr(f, "title", "") or str(getattr(f, "id", ""))
            rule_id = getattr(f, "rule_id", None)
            cvss = getattr(f, "cvss_score", 0) or 0

        key = rule_id or normalize_title(title)
        existing = deduped.get(key)

        if not existing:
            deduped[key] = f
        else:
            # Keep the one with the higher CVSS score
            if isinstance(existing, dict):
                existing_cvss = existing.get("cvss_score") or 0
            else:
                existing_cvss = getattr(existing, "cvss_score", 0) or 0
            if cvss > existing_cvss:
                deduped[key] = f

    return list(deduped.values())
