"""Stored attack-path generation from confirmed findings."""

import json

from app.models.models import AttackPath, Finding, Severity, TriageResult


_CHAIN_RULES = [
    {
        "title": "Credential Theft via Network Interception",
        "keywords": ["cleartext", "http", "certificate", "pinning", "ssl", "tls", "trust all"],
        "description": "An attacker on the same network may intercept traffic and combine weak transport controls with exposed secrets or session material.",
        "score": 8.5,
    },
    {
        "title": "Local Data Extraction",
        "keywords": ["backup", "log", "sharedpreferences", "sqlite", "external storage", "world readable"],
        "description": "An attacker with device or backup access may extract locally stored sensitive data from insecure storage locations.",
        "score": 7.5,
    },
    {
        "title": "Cryptographic Data Exposure",
        "keywords": ["hardcoded", "key", "cipher", "ecb", "md5", "sha1", "crypto", "encrypt"],
        "description": "An attacker who reverse engineers the app may recover weak cryptographic material and decrypt or forge protected data.",
        "score": 8.0,
    },
    {
        "title": "Platform Abuse Through Exposed Components",
        "keywords": ["exported", "intent", "provider", "broadcast", "webview", "deeplink"],
        "description": "A local application or crafted link may abuse exposed Android platform components to trigger sensitive functionality.",
        "score": 7.0,
    },
]


def regenerate_attack_paths(db, scan_id: int) -> list[AttackPath]:
    """Replace stored attack paths for a scan with deterministic chain analysis."""
    db.query(AttackPath).filter(AttackPath.scan_id == scan_id).delete()

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    confirmed = [
        f for f in findings
        if f.triage_result != TriageResult.FALSE_POSITIVE
        and (f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM))
    ]

    paths = []
    used_ids = set()
    for rule in _CHAIN_RULES:
        matched = []
        for f in confirmed:
            haystack = f"{f.title} {f.description or ''} {f.masvs_control or ''}".lower()
            if any(keyword in haystack for keyword in rule["keywords"]):
                matched.append(f)
        if not matched:
            continue
        used_ids.update(f.id for f in matched)
        path = AttackPath(
            scan_id=scan_id,
            title=rule["title"],
            description=_with_finding_context(rule["description"], matched),
            severity=_worst_severity(matched),
            finding_ids=json.dumps([f.id for f in matched]),
            exploitability_score=rule["score"],
        )
        db.add(path)
        paths.append(path)

    for f in confirmed:
        if f.id in used_ids or f.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        path = AttackPath(
            scan_id=scan_id,
            title=f.title[:500],
            description=f.description or "High-impact finding requiring manual review as a standalone attack scenario.",
            severity=f.severity,
            finding_ids=json.dumps([f.id]),
            exploitability_score=9.0 if f.severity == Severity.CRITICAL else 7.0,
        )
        db.add(path)
        paths.append(path)

    db.commit()
    for path in paths:
        db.refresh(path)
    return paths


def _with_finding_context(description: str, findings: list[Finding]) -> str:
    titles = "; ".join(f.title[:90] for f in findings[:4])
    suffix = f" Related evidence: {titles}." if titles else ""
    return description + suffix


def _worst_severity(findings: list[Finding]) -> Severity:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return min((f.severity for f in findings), key=lambda sev: order.get(sev, 5))
