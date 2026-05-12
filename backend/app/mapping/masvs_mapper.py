"""
MASVS Audit Copilot — MASVS v2 Mapper
Maps MobSF findings to OWASP MASVS v2 controls and categories.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ═══════════════════════════════════════════════════════
# MASVS v2 CONTROL DEFINITIONS
# ═══════════════════════════════════════════════════════

MASVS_CATEGORIES = {
    "MASVS-STORAGE": "Data Storage",
    "MASVS-CRYPTO": "Cryptography",
    "MASVS-AUTH": "Authentication & Authorization",
    "MASVS-NETWORK": "Network Communication",
    "MASVS-PLATFORM": "Platform Interaction",
    "MASVS-CODE": "Code Quality",
    "MASVS-RESILIENCE": "Anti-Tampering & Reverse Engineering",
}

MASVS_CONTROLS = {
    # ─── MASVS-STORAGE ───
    "MASVS-STORAGE-1": "Secure storage of sensitive data",
    "MASVS-STORAGE-2": "Prevention of sensitive data leakage",

    # ─── MASVS-CRYPTO ───
    "MASVS-CRYPTO-1": "Use of strong cryptographic algorithms",
    "MASVS-CRYPTO-2": "Proper key management",

    # ─── MASVS-AUTH ───
    "MASVS-AUTH-1": "Secure authentication mechanisms",
    "MASVS-AUTH-2": "Session management",
    "MASVS-AUTH-3": "Authorization controls",

    # ─── MASVS-NETWORK ───
    "MASVS-NETWORK-1": "Secure network communication (TLS)",
    "MASVS-NETWORK-2": "Certificate validation",

    # ─── MASVS-PLATFORM ───
    "MASVS-PLATFORM-1": "Secure use of IPC mechanisms",
    "MASVS-PLATFORM-2": "Secure use of WebViews",
    "MASVS-PLATFORM-3": "Secure use of platform APIs",

    # ─── MASVS-CODE ───
    "MASVS-CODE-1": "Input validation",
    "MASVS-CODE-2": "Secure coding practices",
    "MASVS-CODE-3": "Third-party library security",
    "MASVS-CODE-4": "Protection of sensitive data in memory",

    # ─── MASVS-RESILIENCE ───
    "MASVS-RESILIENCE-1": "Anti-debugging protection",
    "MASVS-RESILIENCE-2": "Root/Jailbreak detection",
    "MASVS-RESILIENCE-3": "Code obfuscation",
    "MASVS-RESILIENCE-4": "Integrity verification",
}


# ═══════════════════════════════════════════════════════
# MOBSF → MASVS MAPPING TABLE
# ═══════════════════════════════════════════════════════

# Maps MobSF finding keywords/types to MASVS controls.
# Each entry: finding_keyword → (masvs_control, default_severity)

MOBSF_TO_MASVS_MAP = {
    # ─── Storage ───
    "hardcoded_secret": ("MASVS-STORAGE-1", "high"),
    "hardcoded_password": ("MASVS-STORAGE-1", "high"),
    "hardcoded_key": ("MASVS-STORAGE-1", "high"),
    "hardcoded_api_key": ("MASVS-STORAGE-1", "high"),
    "shared_preferences": ("MASVS-STORAGE-1", "medium"),
    "external_storage": ("MASVS-STORAGE-1", "medium"),
    "sqlite_database": ("MASVS-STORAGE-1", "medium"),
    "database_encryption": ("MASVS-STORAGE-1", "high"),
    "logging": ("MASVS-STORAGE-2", "low"),
    "clipboard": ("MASVS-STORAGE-2", "medium"),
    "temp_file": ("MASVS-STORAGE-2", "low"),
    "backup_allowed": ("MASVS-STORAGE-2", "medium"),
    "world_readable": ("MASVS-STORAGE-1", "high"),
    "world_writable": ("MASVS-STORAGE-1", "high"),

    # ─── Crypto ───
    "weak_crypto": ("MASVS-CRYPTO-1", "high"),
    "weak_algorithm": ("MASVS-CRYPTO-1", "high"),
    "ecb_mode": ("MASVS-CRYPTO-1", "high"),
    "md5_hash": ("MASVS-CRYPTO-1", "medium"),
    "sha1_hash": ("MASVS-CRYPTO-1", "medium"),
    "des_encryption": ("MASVS-CRYPTO-1", "high"),
    "weak_key_size": ("MASVS-CRYPTO-2", "high"),
    "hardcoded_iv": ("MASVS-CRYPTO-2", "high"),
    "random_insecure": ("MASVS-CRYPTO-1", "medium"),
    "static_iv": ("MASVS-CRYPTO-2", "high"),
    "weak_prng": ("MASVS-CRYPTO-1", "medium"),

    # ─── Auth ───
    "biometric_auth": ("MASVS-AUTH-1", "info"),
    "custom_auth": ("MASVS-AUTH-1", "medium"),

    # ─── Network ───
    "clear_text_traffic": ("MASVS-NETWORK-1", "high"),
    "ssl_pinning": ("MASVS-NETWORK-2", "medium"),
    "insecure_ssl": ("MASVS-NETWORK-1", "critical"),
    "trust_all_certs": ("MASVS-NETWORK-2", "critical"),
    "hostname_verifier": ("MASVS-NETWORK-2", "critical"),
    "http_url": ("MASVS-NETWORK-1", "medium"),
    "network_security_config": ("MASVS-NETWORK-1", "medium"),
    "cleartext_permitted": ("MASVS-NETWORK-1", "high"),

    # ─── Platform ───
    "intent_filter": ("MASVS-PLATFORM-1", "medium"),
    "exported_component": ("MASVS-PLATFORM-1", "high"),
    "content_provider": ("MASVS-PLATFORM-1", "high"),
    "broadcast_receiver": ("MASVS-PLATFORM-1", "medium"),
    "webview_javascript": ("MASVS-PLATFORM-2", "high"),
    "webview_file_access": ("MASVS-PLATFORM-2", "high"),
    "webview_ssl_error": ("MASVS-PLATFORM-2", "critical"),
    "deeplink": ("MASVS-PLATFORM-1", "medium"),
    "implicit_intent": ("MASVS-PLATFORM-1", "medium"),
    "pending_intent": ("MASVS-PLATFORM-1", "high"),

    # ─── Code Quality ───
    "sql_injection": ("MASVS-CODE-1", "critical"),
    "path_traversal": ("MASVS-CODE-1", "high"),
    "command_injection": ("MASVS-CODE-1", "critical"),
    "xss": ("MASVS-CODE-1", "high"),
    "debuggable": ("MASVS-CODE-2", "high"),
    "stack_trace": ("MASVS-CODE-2", "low"),
    "vulnerable_library": ("MASVS-CODE-3", "high"),
    "outdated_library": ("MASVS-CODE-3", "medium"),
    "native_code": ("MASVS-CODE-4", "info"),
    "memory_leak": ("MASVS-CODE-4", "medium"),

    # ─── Resilience ───
    "root_detection": ("MASVS-RESILIENCE-2", "info"),
    "emulator_detection": ("MASVS-RESILIENCE-1", "info"),
    "debugger_detection": ("MASVS-RESILIENCE-1", "info"),
    "obfuscation": ("MASVS-RESILIENCE-3", "info"),
    "code_signing": ("MASVS-RESILIENCE-4", "info"),
    "tamper_detection": ("MASVS-RESILIENCE-4", "info"),
}


# ═══════════════════════════════════════════════════════
# MAPPED FINDING DATA CLASS
# ═══════════════════════════════════════════════════════

@dataclass
class MappedFinding:
    """A MobSF finding mapped to MASVS controls."""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    masvs_category: str  # e.g., MASVS-STORAGE
    masvs_control: str  # e.g., MASVS-STORAGE-1
    mastg_test: Optional[str] = None
    affected_file: Optional[str] = None
    affected_code: Optional[str] = None
    line_number: Optional[int] = None
    source: str = "mobsf"
    raw_data: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════
# MAPPER FUNCTIONS
# ═══════════════════════════════════════════════════════

def _normalize_finding_type(title: str) -> str:
    """
    Normalize a MobSF finding title to a lookup key.
    Converts to lowercase, replaces spaces/dashes with underscores.
    """
    return title.lower().replace(" ", "_").replace("-", "_").strip()


def _find_best_masvs_match(title: str, description: str = "") -> tuple:
    """
    Find the best MASVS mapping for a given finding.

    Returns:
        (masvs_control, default_severity) or (None, None) if no match.
    """
    combined = f"{title} {description}".lower()

    # Direct keyword match
    for keyword, (control, severity) in MOBSF_TO_MASVS_MAP.items():
        if keyword in combined:
            return (control, severity)

    # Fallback: categorize by broader patterns
    pattern_map = [
        (["storage", "file", "database", "log", "shared_pref", "backup"], "MASVS-STORAGE-1"),
        (["crypt", "cipher", "aes", "rsa", "hash", "key", "encrypt"], "MASVS-CRYPTO-1"),
        (["auth", "login", "password", "session", "token", "oauth"], "MASVS-AUTH-1"),
        (["network", "ssl", "tls", "http", "cert", "socket"], "MASVS-NETWORK-1"),
        (["intent", "provider", "webview", "deeplink", "broadcast"], "MASVS-PLATFORM-1"),
        (["inject", "xss", "debug", "library", "memory", "trace"], "MASVS-CODE-1"),
        (["root", "emulator", "tamper", "obfuscat", "integrity"], "MASVS-RESILIENCE-1"),
    ]
    for keywords, control in pattern_map:
        if any(kw in combined for kw in keywords):
            return (control, "medium")

    return (None, None)


def map_findings(mobsf_report: dict) -> List[MappedFinding]:
    """
    Map an entire MobSF report to MASVS v2 controls.

    Processes the following sections of the MobSF JSON report:
    - code_analysis (static source code findings)
    - manifest_analysis (AndroidManifest.xml issues)
    - binary_analysis (binary/native code issues)
    - certificate_analysis (signing certificate issues)
    - network_security (network config findings)

    Args:
        mobsf_report: Complete MobSF JSON report.

    Returns:
        List of MappedFinding objects with MASVS control assignments.
    """
    findings: List[MappedFinding] = []

    # ─── Code Analysis ───
    code_analysis = mobsf_report.get("code_analysis", {})
    code_findings = code_analysis.get("findings", {}) if isinstance(code_analysis, dict) else {}
    if isinstance(code_findings, dict):
        for key, details in code_findings.items():
            if not isinstance(details, dict):
                continue

            metadata = details.get("metadata", {})
            title = metadata.get("description", key)
            description = metadata.get("description", "")
            severity_raw = metadata.get("severity", "info")
            severity = _normalize_severity(severity_raw)

            control, default_sev = _find_best_masvs_match(title, description)
            if not control:
                control = "MASVS-CODE-2"

            category = control.rsplit("-", 1)[0] if control else "MASVS-CODE"

            # Extract affected files
            files = details.get("files", {})
            for filepath, line_info in files.items() if isinstance(files, dict) else []:
                findings.append(MappedFinding(
                    title=title,
                    description=description,
                    severity=severity or default_sev or "info",
                    masvs_category=category,
                    masvs_control=control,
                    affected_file=filepath,
                    line_number=line_info[0] if isinstance(line_info, list) and line_info else None,
                    raw_data=details,
                ))
            if not files:
                findings.append(MappedFinding(
                    title=title,
                    description=description,
                    severity=severity or default_sev or "info",
                    masvs_category=category,
                    masvs_control=control,
                    raw_data=details,
                ))

    # ─── Manifest Analysis ───
    manifest_analysis = mobsf_report.get("manifest_analysis", {})
    manifest_findings = manifest_analysis.get("manifest_findings", []) if isinstance(manifest_analysis, dict) else []
    if isinstance(manifest_findings, list):
        for item in manifest_findings:
            if not isinstance(item, dict):
                continue

            title = item.get("title", "Manifest Issue")
            description = item.get("description", "")
            severity = _normalize_severity(item.get("severity", "info"))

            control, default_sev = _find_best_masvs_match(title, description)
            if not control:
                control = "MASVS-PLATFORM-3"

            category = control.rsplit("-", 1)[0]

            findings.append(MappedFinding(
                title=title,
                description=description,
                severity=severity or default_sev or "info",
                masvs_category=category,
                masvs_control=control,
                affected_file="AndroidManifest.xml",
                raw_data=item,
            ))

    # ─── Network Security ───
    network_security = mobsf_report.get("network_security", {})
    network_findings = network_security.get("network_findings", []) if isinstance(network_security, dict) else []
    if isinstance(network_findings, list):
        for item in network_findings:
            if not isinstance(item, dict):
                continue

            title = item.get("title", item.get("description", "Network Issue"))
            description = item.get("description", "")
            severity = _normalize_severity(item.get("severity", "medium"))

            findings.append(MappedFinding(
                title=title,
                description=description,
                severity=severity,
                masvs_category="MASVS-NETWORK",
                masvs_control="MASVS-NETWORK-1",
                raw_data=item,
            ))

    # ─── Binary Analysis ───
    binary_analysis = mobsf_report.get("binary_analysis", [])
    if isinstance(binary_analysis, list):
        for lib in binary_analysis:
            if not isinstance(lib, dict):
                continue

            lib_name = lib.get("name", "Unknown Library")
            for check_name, check_data in lib.items():
                if check_name == "name" or not isinstance(check_data, dict):
                    continue

                if "severity" not in check_data and "description" not in check_data:
                    continue

                title = f"{check_name.upper()} issue on {lib_name}"
                description = check_data.get("description", "")
                severity = _normalize_severity(check_data.get("severity", "info"))

                # In binary analysis, info means it passed the check. Only add warnings/high/etc.
                if severity == "info":
                    continue

                control, default_sev = _find_best_masvs_match(title, description)
                if not control:
                    control = "MASVS-RESILIENCE-3"

                category = control.rsplit("-", 1)[0]

                findings.append(MappedFinding(
                    title=title,
                    description=description,
                    severity=severity or default_sev or "info",
                    masvs_category=category,
                    masvs_control=control,
                    affected_file=lib_name,
                    raw_data=check_data,
                ))

    return findings


def _normalize_severity(raw: str) -> str:
    """Normalize severity strings from various formats."""
    mapping = {
        "high": "high",
        "warning": "medium",
        "medium": "medium",
        "info": "info",
        "information": "info",
        "low": "low",
        "good": "info",
        "critical": "critical",
        "error": "high",
        "secure": "info",
        "suppressed": "info",
    }
    return mapping.get(raw.lower().strip(), "info")


def get_category_summary(findings: List[MappedFinding]) -> dict:
    """
    Generate a summary of findings grouped by MASVS category.

    Returns:
        Dict with category name → {"total": N, "critical": N, "high": N, ...}
    """
    summary = {}
    for cat_id, cat_name in MASVS_CATEGORIES.items():
        cat_findings = [f for f in findings if f.masvs_category == cat_id]
        summary[cat_id] = {
            "name": cat_name,
            "total": len(cat_findings),
            "critical": sum(1 for f in cat_findings if f.severity == "critical"),
            "high": sum(1 for f in cat_findings if f.severity == "high"),
            "medium": sum(1 for f in cat_findings if f.severity == "medium"),
            "low": sum(1 for f in cat_findings if f.severity == "low"),
            "info": sum(1 for f in cat_findings if f.severity == "info"),
        }
    return summary
