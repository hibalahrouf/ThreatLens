"""Minimal Jira issue creator for confirmed findings."""

import httpx

from app.core.config import settings
from app.models.models import Finding, Severity


def create_issue_for_finding(finding: Finding) -> str | None:
    """Create a Jira issue for a finding when Jira settings are configured."""
    if not all([
        settings.JIRA_BASE_URL,
        settings.JIRA_PROJECT_KEY,
        settings.JIRA_USER_EMAIL,
        settings.JIRA_API_TOKEN,
    ]):
        return None

    priority = _jira_priority(finding.severity)
    labels = ["masvs-audit"]
    if finding.masvs_control:
        labels.append(finding.masvs_control.lower())

    payload = {
        "fields": {
            "project": {"key": settings.JIRA_PROJECT_KEY},
            "summary": f"[{finding.severity.value.upper()}] {finding.title}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": _description_text(finding)}],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "labels": labels,
        }
    }
    url = settings.JIRA_BASE_URL.rstrip("/") + "/rest/api/3/issue"
    response = httpx.post(
        url,
        json=payload,
        auth=(settings.JIRA_USER_EMAIL, settings.JIRA_API_TOKEN),
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("key")


def _description_text(finding: Finding) -> str:
    parts = [
        f"MASVS Control: {finding.masvs_control or 'N/A'}",
        f"CVSS: {finding.cvss_score if finding.cvss_score is not None else 'N/A'}",
        "",
        finding.description or "No description provided.",
    ]
    if finding.remediation_description:
        parts.extend(["", "Recommended remediation:", finding.remediation_description])
    if finding.remediation_code:
        parts.extend(["", "Suggested patch:", finding.remediation_code])
    return "\n".join(parts)


def _jira_priority(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "Highest",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Lowest",
    }.get(severity, "Medium")
