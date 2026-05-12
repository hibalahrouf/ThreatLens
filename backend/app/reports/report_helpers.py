"""
MASVS Audit Copilot — Report Helper Functions
Consulting-grade utilities for PDF report generation.
"""

from typing import List, Dict, Tuple


# ═══════════════════════════════════════════════════════
# FINDING CLASSIFICATION
# ═══════════════════════════════════════════════════════

def split_findings(findings: list) -> Tuple[list, list]:
    """Split findings into confirmed (true positive) and dismissed (false positive)."""
    confirmed, dismissed = [], []
    for f in findings:
        tr = (f.get("triage_result") or "").lower()
        if tr == "false_positive":
            dismissed.append(f)
        else:
            confirmed.append(f)
    return confirmed, dismissed


def count_severities(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ═══════════════════════════════════════════════════════
# BUSINESS IMPACT MAP
# ═══════════════════════════════════════════════════════

_IMPACT_MAP = {
    "MASVS-STORAGE": {
        "critical": "Sensitive user credentials or personal data can be directly extracted from the device, leading to identity theft or unauthorized account access.",
        "high": "Sensitive user data could be extracted from the device by an attacker with physical or backup access.",
        "medium": "Application data may be exposed through insecure local storage mechanisms.",
        "low": "Minor data exposure risk through non-sensitive local storage.",
    },
    "MASVS-CRYPTO": {
        "critical": "Encrypted data can be trivially decrypted, exposing all protected information.",
        "high": "Weak cryptographic implementation may allow attackers to decrypt sensitive data or forge signatures.",
        "medium": "Cryptographic configuration weaknesses reduce the overall protection of stored or transmitted data.",
        "low": "Minor cryptographic improvements recommended for defense-in-depth.",
    },
    "MASVS-AUTH": {
        "critical": "Authentication can be completely bypassed, granting full unauthorized access.",
        "high": "Authentication weaknesses may allow unauthorized access to user accounts.",
        "medium": "Session management issues may allow session hijacking under specific conditions.",
        "low": "Minor authentication hardening recommended.",
    },
    "MASVS-NETWORK": {
        "critical": "All network traffic can be intercepted, exposing credentials and sensitive data.",
        "high": "Man-in-the-middle attacks may expose data in transit to eavesdropping.",
        "medium": "Network configuration weaknesses reduce transport security.",
        "low": "Minor network hardening recommended.",
    },
    "MASVS-PLATFORM": {
        "critical": "Platform-level vulnerabilities allow complete application compromise.",
        "high": "Outdated SDK targets or platform API misuse expose the app to known exploits.",
        "medium": "Platform interaction issues may be exploited under specific conditions.",
        "low": "Platform configuration improvements recommended.",
    },
    "MASVS-CODE": {
        "critical": "Code injection or RCE vulnerability allows complete application takeover.",
        "high": "Code quality issues may be exploited to compromise application integrity.",
        "medium": "Input validation or third-party library issues present moderate risk.",
        "low": "Code quality improvements recommended for robustness.",
    },
    "MASVS-RESILIENCE": {
        "critical": "Application can be trivially reverse-engineered and repackaged with malware.",
        "high": "Insufficient protections allow attackers to analyze and modify the application.",
        "medium": "Reverse engineering protections can be improved.",
        "low": "Additional anti-tampering measures recommended.",
    },
}

_DEFAULT_IMPACT = "This finding may affect the security posture of the application."


def get_business_impact(finding: dict) -> str:
    """Generate a business-impact statement for a finding."""
    cat = finding.get("masvs_category", "")
    sev = (finding.get("severity") or "medium").lower()
    cat_map = _IMPACT_MAP.get(cat, {})
    return cat_map.get(sev, cat_map.get("medium", _DEFAULT_IMPACT))


# ═══════════════════════════════════════════════════════
# MASVS COMPLIANCE MATRIX
# ═══════════════════════════════════════════════════════

def build_compliance_matrix(confirmed: list, dismissed: list) -> list:
    from app.mapping.masvs_mapper import MASVS_CONTROLS, MASVS_CATEGORIES

    failed_controls = set()
    passed_controls = set()
    for f in confirmed:
        ctrl = f.get("masvs_control")
        if ctrl:
            failed_controls.add(ctrl)
    for f in dismissed:
        ctrl = f.get("masvs_control")
        if ctrl and ctrl not in failed_controls:
            passed_controls.add(ctrl)

    matrix = []
    for ctrl_id, ctrl_desc in MASVS_CONTROLS.items():
        cat_id = "-".join(ctrl_id.split("-")[:2])
        cat_name = MASVS_CATEGORIES.get(cat_id, cat_id)
        if ctrl_id in failed_controls:
            status = "FAIL"
        elif ctrl_id in passed_controls:
            status = "PASS"
        else:
            status = "NOT TESTED"
        matrix.append({"control_id": ctrl_id, "description": ctrl_desc, "category": cat_name, "category_id": cat_id, "status": status})
    return matrix


def build_category_heatmap(matrix: list) -> list:
    from app.mapping.masvs_mapper import MASVS_CATEGORIES
    cat_stats = {}
    for cat_id, cat_name in MASVS_CATEGORIES.items():
        cat_stats[cat_id] = {"id": cat_id, "name": cat_name, "pass": 0, "fail": 0, "not_tested": 0}
    for item in matrix:
        cat_id = item["category_id"]
        if cat_id in cat_stats:
            s = item["status"]
            if s == "PASS": cat_stats[cat_id]["pass"] += 1
            elif s == "FAIL": cat_stats[cat_id]["fail"] += 1
            else: cat_stats[cat_id]["not_tested"] += 1
    result = []
    for stats in cat_stats.values():
        stats["overall"] = "ISSUES" if stats["fail"] > 0 else ("PASS" if stats["pass"] > 0 else "NOT TESTED")
        result.append(stats)
    return result


def get_heatmap_summary(heatmap: list) -> str:
    """Generate a one-line summary of which categories have issues."""
    issue_cats = [h["name"] for h in heatmap if h["overall"] == "ISSUES"]
    if not issue_cats:
        return "No issues were detected across any MASVS category."
    if len(issue_cats) == 1:
        return f"Issues are concentrated in {issue_cats[0]}."
    return f"Most issues are concentrated in {', '.join(issue_cats[:-1])} and {issue_cats[-1]}."


# ═══════════════════════════════════════════════════════
# PRIORITY ACTION PLAN
# ═══════════════════════════════════════════════════════

_EFFORT = {"critical": "Immediate", "high": "1-2 days", "medium": "3-5 days", "low": "1-2 weeks", "info": "Backlog"}
_PRIORITY = {"critical": "P0", "high": "P1", "medium": "P1", "low": "P2", "info": "P2"}


def build_priority_plan(confirmed: list) -> dict:
    fix_week, fix_month, monitor = [], [], []
    for f in sorted(confirmed, key=lambda x: x.get("cvss_score") or 0, reverse=True):
        sev = (f.get("severity") or "info").lower()
        entry = {
            "title": _plain_title(f.get("title", "Unknown issue")),
            "severity": sev,
            "masvs_control": f.get("masvs_control", "N/A"),
            "effort": _format_effort(f.get("estimated_effort_hours"), sev),
            "priority": f.get("priority_label") or _PRIORITY.get(sev, "P2"),
        }
        if sev in ("critical", "high"):
            fix_week.append(entry)
        elif sev == "medium":
            fix_month.append(entry)
        else:
            monitor.append(entry)
    return {"fix_week": fix_week, "fix_month": fix_month, "monitor": monitor}


def _plain_title(title: str) -> str:
    """Shorten overly verbose MobSF titles to plain English."""
    if len(title) > 80:
        return title[:77] + "..."
    return title


def _format_effort(hours, severity: str) -> str:
    if hours is None:
        return _EFFORT.get(severity, "TBD")
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        return _EFFORT.get(severity, "TBD")
    if hours <= 0:
        return "Backlog"
    if hours < 8:
        return f"~{hours:g}h"
    days = hours / 8
    return f"~{days:g}d"


# ═══════════════════════════════════════════════════════
# ATTACK SCENARIO CHAINS
# ═══════════════════════════════════════════════════════

_CHAIN_RULES = [
    {
        "name": "Local Data Extraction via ADB",
        "requires": ["backup", "log", "storage", "shared_prefs", "sqlite"],
        "access": "Physical / ADB access",
        "template": "An attacker with USB debugging access can extract application data via ADB backup{details}. This exposes locally stored sensitive information without needing to root the device.",
    },
    {
        "name": "Credential Theft via Network Interception",
        "requires": ["cleartext", "http", "certificate", "pinning", "ssl", "tls"],
        "access": "Network (same WiFi)",
        "template": "An attacker on the same network can intercept application traffic{details}. Combined with missing certificate validation, credentials and session tokens transmitted in transit can be captured.",
    },
    {
        "name": "Cryptographic Data Exposure",
        "requires": ["aes", "ecb", "crypto", "hardcoded", "key", "encrypt", "cipher"],
        "access": "Local / Reverse engineering",
        "template": "Weak cryptographic implementations{details} allow an attacker who reverse-engineers the APK to decrypt locally stored sensitive data or forge cryptographic signatures.",
    },
    {
        "name": "Platform Exploitation via Outdated SDK",
        "requires": ["sdk", "minsdk", "android", "version", "api", "webview", "javascript"],
        "access": "Remote / Local",
        "template": "The application targets outdated Android versions{details}, exposing it to known platform vulnerabilities. Combined with WebView misconfigurations, this may allow remote code execution.",
    },
]


def generate_attack_scenarios(confirmed: list) -> list:
    """Generate real attack-chain scenarios by matching finding keywords against chain rules."""
    if not confirmed:
        return []

    scenarios = []
    used_findings = set()

    for rule in _CHAIN_RULES:
        matched = []
        for i, f in enumerate(confirmed):
            title_desc = ((f.get("title") or "") + " " + (f.get("description") or "")).lower()
            if any(kw in title_desc for kw in rule["requires"]):
                matched.append(f)
                used_findings.add(i)

        if len(matched) >= 1:
            # Build detail string from matched findings
            titles = [f.get("title", "Unknown")[:60] for f in matched[:3]]
            detail_str = " (" + " + ".join(titles) + ")" if titles else ""
            narrative = rule["template"].replace("{details}", detail_str)
            worst_sev = _worst_severity([f.get("severity", "low") for f in matched])

            scenarios.append({
                "name": rule["name"],
                "access": rule["access"],
                "narrative": narrative,
                "severity": worst_sev,
                "finding_count": len(matched),
                "findings": titles,
            })

    # Fallback: unmatched high/critical findings get their own entry
    for i, f in enumerate(confirmed):
        if i not in used_findings and (f.get("severity") or "").lower() in ("critical", "high"):
            scenarios.append({
                "name": f.get("title", "Unclassified Risk")[:60],
                "access": "Varies",
                "narrative": get_business_impact(f),
                "severity": (f.get("severity") or "medium").lower(),
                "finding_count": 1,
                "findings": [f.get("title", "Unknown")[:60]],
            })

    # Sort by severity, limit to 3
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    scenarios.sort(key=lambda s: sev_order.get(s["severity"], 4))
    return scenarios[:3]


def _worst_severity(sevs: list) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return min(sevs, key=lambda s: order.get(s.lower(), 4))


# ═══════════════════════════════════════════════════════
# EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════════════

def generate_executive_summary(scan_data: dict, confirmed: list, dismissed: list) -> str:
    """Generate a concrete, risk-driven executive summary."""
    score = scan_data.get("score", 0) or 0
    grade = scan_data.get("grade", "?")
    app = scan_data.get("file_name", "the application")
    n_confirmed = len(confirmed)
    n_dismissed = len(dismissed)
    sev = count_severities(confirmed)

    # Find the single biggest concrete risk
    biggest_risk = "no critical vulnerabilities"
    recommendation = "Maintain current security practices and monitor for new threats."
    if confirmed:
        worst = max(confirmed, key=lambda f: f.get("cvss_score") or 0)
        biggest_risk = worst.get("title", "an unspecified vulnerability")
        # Generate specific recommendation based on worst finding
        worst_cat = worst.get("masvs_category", "")
        if "STORAGE" in worst_cat:
            recommendation = "Disable android:allowBackup and audit all local data storage for sensitive information."
        elif "CRYPTO" in worst_cat:
            recommendation = "Replace weak cipher configurations (ECB mode, hardcoded keys) with AES-GCM and secure key management."
        elif "NETWORK" in worst_cat:
            recommendation = "Enforce TLS for all connections and implement certificate pinning."
        elif "PLATFORM" in worst_cat:
            recommendation = "Raise minSdkVersion to API 29+ and audit WebView configurations."
        elif "CODE" in worst_cat:
            recommendation = "Update vulnerable third-party libraries and implement input validation."
        elif "RESILIENCE" in worst_cat:
            recommendation = "Enable code obfuscation (ProGuard/R8) and add root/tamper detection."
        else:
            recommendation = "Address the highest-severity finding before the next release."

    # Build summary
    parts = []
    parts.append(f"The security assessment of {app} resulted in a score of {score:.1f}/100 (Grade {grade}).")
    parts.append(f"Out of {n_confirmed + n_dismissed} total findings, {n_confirmed} {'was' if n_confirmed == 1 else 'were'} confirmed as real {'vulnerability' if n_confirmed == 1 else 'vulnerabilities'} and {n_dismissed} {'was' if n_dismissed == 1 else 'were'} dismissed as false positives by AI triage.")

    if sev["critical"] > 0:
        parts.append(f"The most urgent risk is: {biggest_risk}.")
    elif sev["high"] > 0:
        parts.append(f"The primary risk identified is: {biggest_risk}.")
    else:
        parts.append(f"No critical or high-severity vulnerabilities were found.")

    parts.append(f"Recommended action: {recommendation}")
    return " ".join(parts)
