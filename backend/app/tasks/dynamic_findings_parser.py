"""
MASVS Audit Copilot — Dynamic Findings Parser
Transforms a MobSF dynamic analysis report into a normalised list of
finding dicts ready for database insertion.

Each dict contains:
    title, masvs_control, source, severity, description, scan_id

Mapping table:
    MobSF Section             → MASVS Control        → source    → severity
    ─────────────────────────────────────────────────────────────────────────
    HTTP URLs in traffic      → MASVS-NETWORK-1      → network   → high
    Certificate issues        → MASVS-NETWORK-2      → network   → high
    Exported components       → MASVS-PLATFORM-1     → dynamic   → high
    Crypto calls (frida)      → MASVS-CRYPTO-1       → frida     → high
    Sensitive data in memory  → MASVS-CODE-4         → frida     → medium
    Root detection bypass     → MASVS-RESILIENCE-2   → frida     → high
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_dynamic_findings(scan_id: int, dynamic_report: dict) -> list[dict]:
    """
    Parse a MobSF dynamic analysis JSON report into a flat list of
    normalised finding dicts.

    Args:
        scan_id: The database scan ID to associate findings with.
        dynamic_report: The raw MobSF dynamic report dict.

    Returns:
        A list of finding dicts.  Empty list if the report is empty
        or malformed — this function never crashes.
    """
    findings: list[dict] = []

    if not isinstance(dynamic_report, dict):
        logger.warning("dynamic_report is not a dict — returning empty findings")
        return findings

    # ── 1. HTTP URLs in traffic (MASVS-NETWORK-1) ───────────────────────
    _parse_http_urls(scan_id, dynamic_report, findings)

    # ── 2. Certificate issues (MASVS-NETWORK-2) ─────────────────────────
    _parse_certificate_issues(scan_id, dynamic_report, findings)

    # ── 3. Runtime exported components (MASVS-PLATFORM-1) ───────────────
    _parse_exported_components(scan_id, dynamic_report, findings)

    # ── 4. Crypto calls in frida logs (MASVS-CRYPTO-1) ──────────────────
    _parse_crypto_calls(scan_id, dynamic_report, findings)

    # ── 5. Sensitive data in memory (MASVS-CODE-4) ──────────────────────
    _parse_sensitive_memory(scan_id, dynamic_report, findings)

    # ── 6. Root detection bypass (MASVS-RESILIENCE-2) ───────────────────
    _parse_root_detection(scan_id, dynamic_report, findings)

    logger.info(
        "Parsed %d dynamic findings for scan_id=%d", len(findings), scan_id,
    )
    return findings


# ─── Internal Parsers ────────────────────────────────────────────────────────
# Each parser follows the same contract:
#   - Append to `findings` list in-place
#   - Skip silently on missing / malformed keys (never crash)
#   - Only include a finding if title AND masvs_control are non-empty


def _safe_append(findings: list[dict], finding: dict) -> None:
    """Only append if title and masvs_control are both non-empty strings."""
    title = finding.get("title", "")
    control = finding.get("masvs_control", "")
    if title and control:
        findings.append(finding)


# ── 1. HTTP URLs in traffic ──────────────────────────────────────────────────

def _parse_http_urls(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract cleartext HTTP URLs captured during dynamic analysis."""
    try:
        # MobSF stores network traffic URLs under various keys depending
        # on version.  Check the most common ones.
        urls: list[Any] = []

        # v4.x: "urls" list or "network_traffic" dict
        if isinstance(report.get("urls"), list):
            urls = report["urls"]
        elif isinstance(report.get("network_traffic"), dict):
            for _key, val in report["network_traffic"].items():
                if isinstance(val, list):
                    urls.extend(val)

        # Also check "httptools" key used by some MobSF builds
        if isinstance(report.get("httptools"), list):
            urls.extend(report["httptools"])

        http_urls = [
            u for u in urls
            if isinstance(u, str) and u.lower().startswith("http://")
        ]

        for url_str in http_urls:
            _safe_append(findings, {
                "title": f"Cleartext HTTP traffic detected: {url_str[:200]}",
                "masvs_control": "MASVS-NETWORK-1",
                "source": "network",
                "severity": "high",
                "description": (
                    f"The application made an unencrypted HTTP request to "
                    f"{url_str[:500]}.  All network traffic should use TLS "
                    f"to prevent interception."
                ),
                "scan_id": scan_id,
            })

        # If the report has a dedicated "cleartext" flag or summary
        if report.get("cleartext_summary"):
            _safe_append(findings, {
                "title": "Cleartext network traffic summary",
                "masvs_control": "MASVS-NETWORK-1",
                "source": "network",
                "severity": "high",
                "description": str(report["cleartext_summary"])[:2000],
                "scan_id": scan_id,
            })

    except Exception:
        logger.debug("_parse_http_urls: skipped due to missing/malformed data")


# ── 2. Certificate issues ───────────────────────────────────────────────────

def _parse_certificate_issues(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract TLS/SSL certificate validation issues."""
    try:
        # MobSF stores TLS test results under "tls_tests" or "ssl_pinning"
        tls_tests = report.get("tls_tests") or report.get("ssl_pinning") or {}

        if isinstance(tls_tests, dict):
            items = tls_tests.items() if tls_tests else []
            for test_name, result in items:
                status = ""
                desc = ""
                if isinstance(result, dict):
                    status = str(result.get("status", "")).lower()
                    desc = str(result.get("description", result.get("info", "")))
                elif isinstance(result, str):
                    status = result.lower()
                    desc = result

                if status in ("fail", "warning", "insecure", "vulnerable"):
                    _safe_append(findings, {
                        "title": f"Certificate issue: {test_name}",
                        "masvs_control": "MASVS-NETWORK-2",
                        "source": "network",
                        "severity": "high",
                        "description": desc[:2000] or f"TLS test '{test_name}' failed.",
                        "scan_id": scan_id,
                    })

        elif isinstance(tls_tests, list):
            for item in tls_tests:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("status", "")).lower()
                if status in ("fail", "warning", "insecure", "vulnerable"):
                    title = item.get("test", item.get("title", "Certificate validation issue"))
                    _safe_append(findings, {
                        "title": str(title)[:500],
                        "masvs_control": "MASVS-NETWORK-2",
                        "source": "network",
                        "severity": "high",
                        "description": str(item.get("description", ""))[:2000],
                        "scan_id": scan_id,
                    })

    except Exception:
        logger.debug("_parse_certificate_issues: skipped due to missing/malformed data")


# ── 3. Runtime exported components ──────────────────────────────────────────

def _parse_exported_components(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract exported activities/services/receivers found at runtime."""
    try:
        # MobSF stores exported components under "exported_activities",
        # "exported_count", or nested within "activities" / "test_results".
        component_keys = [
            "exported_activities", "exported_services",
            "exported_receivers", "exported_providers",
        ]

        for key in component_keys:
            components = report.get(key)
            if not components:
                continue

            if isinstance(components, list):
                for comp in components:
                    comp_name = str(comp) if not isinstance(comp, dict) else comp.get("name", str(comp))
                    _safe_append(findings, {
                        "title": f"Exported component at runtime: {comp_name[:300]}",
                        "masvs_control": "MASVS-PLATFORM-1",
                        "source": "dynamic",
                        "severity": "high",
                        "description": (
                            f"The component '{comp_name}' is exported and accessible "
                            f"to other applications at runtime.  This may allow "
                            f"unauthorised access to application functionality."
                        ),
                        "scan_id": scan_id,
                    })

        # Also check the "test_results" section for activity tests
        test_results = report.get("test_results") or report.get("activity_tester") or {}
        if isinstance(test_results, dict):
            for act_name, result in test_results.items():
                if isinstance(result, dict) and result.get("exported"):
                    _safe_append(findings, {
                        "title": f"Exported activity confirmed: {act_name[:300]}",
                        "masvs_control": "MASVS-PLATFORM-1",
                        "source": "dynamic",
                        "severity": "high",
                        "description": (
                            f"Activity '{act_name}' was confirmed exported during "
                            f"runtime testing."
                        ),
                        "scan_id": scan_id,
                    })

    except Exception:
        logger.debug("_parse_exported_components: skipped due to missing/malformed data")


# ── 4. Crypto calls in frida logs ───────────────────────────────────────────

def _parse_crypto_calls(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract weak cryptography usage detected via Frida instrumentation."""
    try:
        frida_logs = report.get("frida_logs") or report.get("frida") or {}

        crypto_keywords = [
            "DES", "RC4", "MD5", "SHA1", "ECB", "Blowfish",
            "Cipher.getInstance", "SecretKeySpec", "MessageDigest",
        ]

        log_text = ""
        if isinstance(frida_logs, str):
            log_text = frida_logs
        elif isinstance(frida_logs, dict):
            log_text = str(frida_logs.get("data", "")) + str(frida_logs.get("logs", ""))
        elif isinstance(frida_logs, list):
            log_text = "\n".join(str(entry) for entry in frida_logs)

        detected = [kw for kw in crypto_keywords if kw.lower() in log_text.lower()]

        if detected:
            _safe_append(findings, {
                "title": f"Weak cryptography detected via Frida: {', '.join(detected)}",
                "masvs_control": "MASVS-CRYPTO-1",
                "source": "frida",
                "severity": "high",
                "description": (
                    f"Frida instrumentation detected usage of potentially weak "
                    f"cryptographic primitives: {', '.join(detected)}.  "
                    f"Consider using AES-GCM or ChaCha20-Poly1305."
                ),
                "scan_id": scan_id,
            })

        # Also check "api_monitor" for crypto API calls
        api_monitor = report.get("api_monitor") or {}
        if isinstance(api_monitor, dict):
            crypto_apis = api_monitor.get("crypto") or api_monitor.get("Crypto") or []
            if isinstance(crypto_apis, list) and crypto_apis:
                _safe_append(findings, {
                    "title": "Cryptographic API calls detected at runtime",
                    "masvs_control": "MASVS-CRYPTO-1",
                    "source": "frida",
                    "severity": "high",
                    "description": (
                        f"Runtime monitoring detected {len(crypto_apis)} "
                        f"cryptographic API call(s) that may use insecure algorithms."
                    ),
                    "scan_id": scan_id,
                })

    except Exception:
        logger.debug("_parse_crypto_calls: skipped due to missing/malformed data")


# ── 5. Sensitive data in memory ─────────────────────────────────────────────

def _parse_sensitive_memory(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract sensitive data found in application memory at runtime."""
    try:
        # MobSF may store memory analysis under "memory" or "heap_dump"
        memory_data = report.get("memory") or report.get("heap_dump") or {}

        sensitive_patterns = [
            "password", "token", "secret", "api_key", "apikey",
            "private_key", "credit_card", "ssn", "session",
        ]

        mem_text = ""
        if isinstance(memory_data, str):
            mem_text = memory_data
        elif isinstance(memory_data, dict):
            mem_text = str(memory_data)
        elif isinstance(memory_data, list):
            mem_text = "\n".join(str(item) for item in memory_data)

        detected = [p for p in sensitive_patterns if p.lower() in mem_text.lower()]

        if detected:
            _safe_append(findings, {
                "title": f"Sensitive data found in memory: {', '.join(detected[:5])}",
                "masvs_control": "MASVS-CODE-4",
                "source": "frida",
                "severity": "medium",
                "description": (
                    f"Runtime memory analysis detected potential sensitive data "
                    f"patterns ({', '.join(detected)}) remaining in application memory.  "
                    f"Sensitive data should be zeroed out after use."
                ),
                "scan_id": scan_id,
            })

        # Also check Frida heap search results
        frida_heap = report.get("frida_heap") or {}
        if isinstance(frida_heap, dict) and frida_heap:
            _safe_append(findings, {
                "title": "Sensitive data detected in heap via Frida",
                "masvs_control": "MASVS-CODE-4",
                "source": "frida",
                "severity": "medium",
                "description": (
                    "Frida heap analysis found sensitive data references "
                    "persisting in application memory."
                ),
                "scan_id": scan_id,
            })

    except Exception:
        logger.debug("_parse_sensitive_memory: skipped due to missing/malformed data")


# ── 6. Root detection bypass ────────────────────────────────────────────────

def _parse_root_detection(
    scan_id: int, report: dict, findings: list[dict],
) -> None:
    """Extract root/jailbreak detection bypass findings."""
    try:
        # Check various keys where MobSF stores root detection info
        root_keys = [
            "root_detection", "root_check", "jailbreak_detection",
            "anti_root", "SafetyNet",
        ]

        for key in root_keys:
            value = report.get(key)
            if value is None:
                continue

            bypassed = False
            desc = ""

            if isinstance(value, dict):
                status = str(value.get("status", "")).lower()
                bypassed = status in ("bypassed", "failed", "not_detected", "absent")
                desc = str(value.get("description", value.get("info", "")))
            elif isinstance(value, str):
                bypassed = value.lower() in ("bypassed", "failed", "no", "absent", "not found")
                desc = value
            elif isinstance(value, bool):
                bypassed = not value  # False means no root detection

            if bypassed:
                _safe_append(findings, {
                    "title": f"Root detection bypass: {key}",
                    "masvs_control": "MASVS-RESILIENCE-2",
                    "source": "frida",
                    "severity": "high",
                    "description": (
                        desc[:2000] or
                        f"The application's root/jailbreak detection ({key}) "
                        f"was bypassed during dynamic analysis.  The app should "
                        f"implement multi-layered root detection."
                    ),
                    "scan_id": scan_id,
                })

        # Frida scripts may also log root bypass attempts
        frida_logs = report.get("frida_logs") or report.get("frida") or ""
        log_text = str(frida_logs) if not isinstance(frida_logs, str) else frida_logs

        root_bypass_keywords = [
            "root bypass", "su binary", "magisk", "supersu",
            "root detected: false", "rooted: false",
        ]

        for keyword in root_bypass_keywords:
            if keyword.lower() in log_text.lower():
                _safe_append(findings, {
                    "title": f"Root detection bypass indicator: {keyword}",
                    "masvs_control": "MASVS-RESILIENCE-2",
                    "source": "frida",
                    "severity": "high",
                    "description": (
                        f"Frida logs contain root detection bypass indicator "
                        f"'{keyword}'.  The application's integrity checks may "
                        f"be insufficient."
                    ),
                    "scan_id": scan_id,
                })
                break  # One finding is enough for Frida root bypass

    except Exception:
        logger.debug("_parse_root_detection: skipped due to missing/malformed data")
