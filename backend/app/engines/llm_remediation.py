"""
MASVS Audit Copilot — LLM Auto-Remediation Engine
Generates code patches for confirmed vulnerabilities using an LLM.
"""

import json
from typing import Optional
from dataclasses import dataclass

from app.core.config import settings
from app.engines.llm_triage import LLMClient


@dataclass
class RemediationResult:
    """Generated code patch for a finding."""
    finding_id: int
    description: str  # Human-readable explanation
    code_patch: str  # Code diff (Kotlin/Swift/Java)
    language: str  # kotlin, swift, java
    confidence: float  # 0.0 to 1.0
    validated: bool  # Whether the critic pass approved it


# ═══════════════════════════════════════════════════════
# PROMPT TEMPLATES
# ═══════════════════════════════════════════════════════

REMEDIATION_SYSTEM_PROMPT = """You are a mobile security expert. Respond ONLY with a valid JSON object, no markdown, no explanation outside the JSON.
The JSON must have exactly these 3 fields:
- "description": a string explaining the fix in plain English
- "code_patch": a string with the fixed code (use \n for newlines, escape all quotes with \")
- "confidence": a number between 0.0 and 1.0
Example: {"description": "Replace ECB with GCM mode", "code_patch": "val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")", "confidence": 0.9}"""

REMEDIATION_USER_PROMPT = """Fix this security vulnerability in a mobile application:

**Vulnerability:** {title}
**Severity:** {severity}
**MASVS Control:** {masvs_control}
**MASTG Reference:** {mastg_test}
**Affected File:** {affected_file}

Vulnerable code: {vulnerable_code}

**Description:**
{description}

Provide a secure code fix following MASTG guidelines for {masvs_control}."""

CRITIC_SYSTEM_PROMPT = """You are a senior mobile security reviewer. Your ONLY job is to validate whether a proposed code fix actually addresses the security vulnerability it claims to fix.

Check for:
1. Does the fix actually resolve the vulnerability?
2. Does it introduce any NEW vulnerabilities?
3. Is it using the correct, up-to-date APIs?
4. Is the fix complete or does it miss edge cases?

Respond in JSON:
{
    "approved": true/false,
    "issues": ["list of issues if not approved"],
    "suggestions": "optional improvements"
}"""


# ═══════════════════════════════════════════════════════
# REMEDIATION FUNCTIONS
# ═══════════════════════════════════════════════════════

def _clean_json(text: str) -> str:
    import re

    text = text.strip()
    if text.startswith("```json"):
        text = text[len("```json"):].strip()
    if text.startswith("```"):
        text = text[len("```"):].strip()
    if text.endswith("```"):
        text = text[:-len("```")].strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and start < end:
        text = text[start:end + 1]
    try:
        json.loads(text)
    except Exception:
        match = re.search(r'"description"\s*:\s*"([^"]+)"', text)
        if match:
            return json.dumps({
                "description": match.group(1),
                "code_patch": "",
                "confidence": 0.5,
            })
    return text


def generate_remediation(
    finding_id: int,
    title: str,
    severity: str,
    masvs_control: str,
    description: str = "",
    affected_file: str = "",
    vulnerable_code: str = "",
    mastg_test: str = "",
    language: str = "kotlin",
    validate: bool = True,
) -> RemediationResult:
    """
    Generate a secure code fix for a vulnerability using an LLM.

    Includes an optional second "critic" pass to validate the fix.

    Args:
        finding_id: Database ID of the finding.
        title: Vulnerability title.
        severity: Severity level.
        masvs_control: MASVS control ID.
        description: Vulnerability description.
        affected_file: Path to the affected file.
        vulnerable_code: The vulnerable code snippet.
        mastg_test: MASTG test reference.
        language: Target language (kotlin, swift, java).
        validate: Whether to run the critic validation pass.

    Returns:
        RemediationResult with the generated code fix.
    """
    llm = LLMClient()

    # ─── Pass 1: Generate the fix ───
    user_prompt = REMEDIATION_USER_PROMPT.format(
        title=title,
        severity=severity,
        masvs_control=masvs_control,
        mastg_test=mastg_test or "N/A",
        affected_file=affected_file or "N/A",
        language=language,
        vulnerable_code=vulnerable_code or "No code available",
        description=description or "No additional description.",
    )

    try:
        response = llm.chat(
            system_prompt=REMEDIATION_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            json_mode=True,
            max_tokens=2000,
        )
        result = json.loads(_clean_json(response))

        code_patch = result.get("code_patch", "")
        fix_description = result.get("description", "")
        fix_language = result.get("language", language)
        confidence = float(result.get("confidence", 0.5))

        # ─── Pass 2: Critic validation ───
        validated = False
        if validate and code_patch:
            validated = _validate_fix(
                llm,
                title=title,
                masvs_control=masvs_control,
                vulnerable_code=vulnerable_code,
                fix_code=code_patch,
            )
            if validated:
                confidence = min(confidence + 0.15, 1.0)

        return RemediationResult(
            finding_id=finding_id,
            description=fix_description,
            code_patch=code_patch,
            language=fix_language,
            confidence=confidence,
            validated=validated,
        )

    except Exception as e:
        return RemediationResult(
            finding_id=finding_id,
            description=f"Auto-remediation failed: {str(e)}",
            code_patch="",
            language=language,
            confidence=0.0,
            validated=False,
        )


def _validate_fix(
    llm: LLMClient,
    title: str,
    masvs_control: str,
    vulnerable_code: str,
    fix_code: str,
) -> bool:
    """
    Run a critic LLM pass to validate the proposed fix.

    Returns True if the fix is approved.
    """
    critic_prompt = f"""Validate this security fix:

**Vulnerability:** {title}
**MASVS Control:** {masvs_control}

**Original vulnerable code:**
```
{vulnerable_code}
```

**Proposed fix:**
```
{fix_code}
```

Does this fix properly address the vulnerability without introducing new issues?"""

    try:
        response = llm.chat(
            system_prompt=CRITIC_SYSTEM_PROMPT,
            user_prompt=critic_prompt,
            json_mode=True,
            max_tokens=1500,
        )
        result = json.loads(_clean_json(response))
        return result.get("approved", False)
    except Exception:
        return False
