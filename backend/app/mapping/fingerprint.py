"""
MASVS Audit Copilot — Finding Fingerprint Generator
Creates stable SHA-256 hashes for each finding to enable version comparison.
"""

import hashlib
from typing import List

from app.mapping.masvs_mapper import MappedFinding


def generate_fingerprint(finding: MappedFinding) -> str:
    """
    Generate a stable fingerprint (SHA-256) for a finding.

    The fingerprint is based on:
    - Vulnerability type (title)
    - Affected component (file path)
    - MASVS control ID

    This allows identifying the SAME finding across two versions
    of an application, even if line numbers change.

    Args:
        finding: A mapped finding.

    Returns:
        64-character hex SHA-256 hash.
    """
    components = [
        finding.title.lower().strip(),
        (finding.affected_file or "unknown").lower().strip(),
        (finding.masvs_control or "unknown").strip(),
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_fingerprints(findings: List[MappedFinding]) -> dict:
    """
    Generate fingerprints for all findings.

    Returns:
        Dict mapping fingerprint → MappedFinding.
    """
    result = {}
    for finding in findings:
        fp = generate_fingerprint(finding)
        result[fp] = finding
    return result


def diff_scans(
    fingerprints_old: dict,
    fingerprints_new: dict,
) -> dict:
    """
    Compare two sets of fingerprints to identify changes between versions.

    Args:
        fingerprints_old: Fingerprints from the older scan.
        fingerprints_new: Fingerprints from the newer scan.

    Returns:
        Dict with three lists:
        - "new": Findings only in the new scan (introduced)
        - "fixed": Findings only in the old scan (corrected)
        - "persistent": Findings in both scans (still present)
    """
    old_keys = set(fingerprints_old.keys())
    new_keys = set(fingerprints_new.keys())

    return {
        "new": [fingerprints_new[k] for k in new_keys - old_keys],
        "fixed": [fingerprints_old[k] for k in old_keys - new_keys],
        "persistent": [fingerprints_new[k] for k in old_keys & new_keys],
    }
