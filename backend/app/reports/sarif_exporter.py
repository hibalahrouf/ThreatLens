"""
MASVS Audit Copilot — SARIF 2.1 Exporter
Generates SARIF (Static Analysis Results Interchange Format) reports.
Compatible with GitHub Security, GitLab SAST, and Azure DevOps.
"""

import json
from datetime import datetime, timezone
from typing import List


def generate_sarif_report(
    scan_data: dict,
    findings: list,
    output_path: str,
) -> str:
    """
    Generate a SARIF 2.1.0 report.

    SARIF is the standard format for static analysis results.
    This output is directly compatible with:
    - GitHub Security tab (code scanning alerts)
    - GitLab SAST
    - Azure DevOps

    Args:
        scan_data: Scan metadata.
        findings: List of finding dictionaries.
        output_path: Path to save the SARIF JSON file.

    Returns:
        Path to the generated file.
    """
    # Build rules (one per unique finding type)
    rules = {}
    results = []

    for finding in findings:
        rule_id = _make_rule_id(finding)

        # Add rule if not already defined
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": _sanitize_name(finding.get("title", "Unknown")),
                "shortDescription": {
                    "text": finding.get("title", "Security Finding"),
                },
                "fullDescription": {
                    "text": finding.get("description", "No description available."),
                },
                "helpUri": f"https://mas.owasp.org/MASVS/controls/{finding.get('masvs_control', '')}",
                "properties": {
                    "tags": [
                        finding.get("masvs_category", "security"),
                        finding.get("masvs_control", ""),
                        "MASVS",
                    ],
                    "security-severity": str(_severity_to_score(finding.get("severity", "info"))),
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(finding.get("severity", "info")),
                },
            }

        # Build result
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules.keys()).index(rule_id),
            "level": _severity_to_sarif_level(finding.get("severity", "info")),
            "message": {
                "text": _build_message(finding),
            },
            "locations": [],
            "properties": {
                "masvs_category": finding.get("masvs_category", ""),
                "masvs_control": finding.get("masvs_control", ""),
                "cvss_score": finding.get("cvss_score"),
                "cvss_vector": finding.get("cvss_vector", ""),
                "triage_result": finding.get("triage_result", "not_triaged"),
                "fingerprint": finding.get("fingerprint", ""),
            },
        }

        # Add location if available
        if finding.get("affected_file"):
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding["affected_file"],
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
            if finding.get("line_number"):
                location["physicalLocation"]["region"] = {
                    "startLine": finding["line_number"],
                }
            result["locations"].append(location)

        # Add code fix if available
        if finding.get("remediation_code"):
            result["fixes"] = [{
                "description": {
                    "text": finding.get("remediation_description", "Apply the following fix"),
                },
                "artifactChanges": [{
                    "artifactLocation": {
                        "uri": finding.get("affected_file", "unknown"),
                    },
                    "replacements": [{
                        "insertedContent": {
                            "text": finding["remediation_code"],
                        },
                    }],
                }],
            }]

        results.append(result)

    # Build SARIF document
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MASVS Audit Copilot",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/masvs-copilot",
                    "rules": list(rules.values()),
                    "properties": {
                        "scanScore": scan_data.get("score"),
                        "scanGrade": scan_data.get("grade"),
                    },
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": scan_data.get("started_at", datetime.now(timezone.utc).isoformat()),
                "endTimeUtc": scan_data.get("completed_at", datetime.now(timezone.utc).isoformat()),
            }],
        }],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, default=str)

    return output_path


def _make_rule_id(finding: dict) -> str:
    """Generate a SARIF rule ID from a finding."""
    control = finding.get("masvs_control", "UNKNOWN")
    title = _sanitize_name(finding.get("title", "finding"))
    return f"{control}/{title}"


def _sanitize_name(name: str) -> str:
    """Sanitize a string for use as a SARIF name."""
    return name.replace(" ", "_").replace("/", "-")[:64]


def _severity_to_sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity.lower(), "note")


def _severity_to_score(severity: str) -> float:
    """Map severity to a SARIF security-severity score."""
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
        "info": 1.0,
    }.get(severity.lower(), 1.0)


def _build_message(finding: dict) -> str:
    """Build a SARIF result message."""
    parts = [finding.get("title", "Security Finding")]
    if finding.get("masvs_control"):
        parts.append(f"[{finding['masvs_control']}]")
    if finding.get("description"):
        parts.append(f"— {finding['description'][:200]}")
    return " ".join(parts)
