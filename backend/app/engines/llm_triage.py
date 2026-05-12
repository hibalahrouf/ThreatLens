"""
MASVS Audit Copilot — LLM Triage Engine
Uses an LLM to determine if each finding is a true positive or false positive.
"""

from typing import Optional, List, Tuple
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class TriageDecision:
    """Result of LLM triage for a single finding."""
    finding_id: int
    is_true_positive: bool
    confidence: float  # 0.0 to 1.0
    justification: str
    suggested_severity: Optional[str] = None  # May down/upgrade severity


# ═══════════════════════════════════════════════════════
# PROMPT TEMPLATES
# ═══════════════════════════════════════════════════════

TRIAGE_SYSTEM_PROMPT = """You are an expert mobile application security auditor specializing in the OWASP MASTG (Mobile Application Security Testing Guide). Your task is to analyze security findings from automated static analysis and determine if each finding is a TRUE POSITIVE (real vulnerability) or a FALSE POSITIVE (not exploitable or not applicable).

When analyzing each finding, consider:
1. The context of the code — is the sensitive data actually sensitive, or is it a public constant?
2. Whether the vulnerability is actually exploitable in a mobile app context.
3. The MASVS v2 control it maps to, and whether the control is applicable.
4. Common false positive patterns in static analysis tools.

Respond in JSON format:
{
    "is_true_positive": true/false,
    "confidence": 0.0-1.0,
    "justification": "Clear explanation of your reasoning",
    "suggested_severity": "critical|high|medium|low|info|null"
}"""

TRIAGE_USER_PROMPT = """Analyze this security finding from a mobile app static analysis:

**Finding:** {title}
**Severity:** {severity}
**MASVS Control:** {masvs_control} - {masvs_description}
**Affected File:** {affected_file}

**Description:**
{description}

**Code Context (if available):**
```
{code_context}
```

**Historical Auditor Feedback (if available):**
{historical_feedback}

Is this a TRUE POSITIVE or FALSE POSITIVE? Explain your reasoning based on MASTG guidelines."""


# ═══════════════════════════════════════════════════════
# LLM CLIENT ABSTRACTION
# ═══════════════════════════════════════════════════════

class LLMClient:
    """
    Abstraction layer for multiple LLM providers.
    Supports: OpenAI, Ollama (local), Gemini.
    """

    def __init__(self, provider: Optional[str] = None):
        self.provider = provider or settings.LLM_PROVIDER

    def chat(self, system_prompt: str, user_prompt: str, json_mode: bool = False, max_tokens: int = 350) -> str:
        """
        Send a chat message to the configured LLM provider.

        Args:
            system_prompt: System instruction.
            user_prompt: User message.
            json_mode: Whether to request JSON output format.
            max_tokens: Maximum tokens to generate.

        Returns:
            LLM response text.
        """
        if self.provider == "openai":
            if not settings.OPENAI_API_KEY or "your_openai_api_key_here" in settings.OPENAI_API_KEY:
                # Fallback to ollama if openai is selected but key is missing
                self.provider = "ollama"
            else:
                return self._chat_openai(system_prompt, user_prompt, json_mode, max_tokens)
        
        if self.provider == "ollama":
            return self._chat_ollama(system_prompt, user_prompt, json_mode, max_tokens)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    def _chat_openai(self, system_prompt: str, user_prompt: str, json_mode: bool, max_tokens: int) -> str:
        """Call OpenAI API."""
        from openai import OpenAI

        client = OpenAI(api_key=settings.OPENAI_API_KEY)

        kwargs = {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,  # Low temperature for consistent triage
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content

    def _chat_ollama(self, system_prompt: str, user_prompt: str, json_mode: bool, max_tokens: int) -> str:
        """Call local Ollama API."""
        import httpx

        payload = {
            "model": "llama3",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": max_tokens,
            },
        }
        if json_mode:
            payload["format"] = "json"

        with httpx.Client(timeout=180) as client:
            response = client.post(
                f"{settings.OLLAMA_URL}/api/chat",
                json=payload,
            )
            response.raise_for_status()
            return response.json()["message"]["content"]


# ═══════════════════════════════════════════════════════
# RULE-BASED PRE-TRIAGE
# ═══════════════════════════════════════════════════════

_RULE_KEYWORDS = {
    "MASVS-RESILIENCE-1": {
        "keywords": ["root", "su", "superuser", "magisk", "daemonsu", "test-keys", "jailbreak"],
        "verdict": "CONFIRMED",
        "justification": "Root-related behavior detected in the finding. This is a confirmed security concern per MASVS-RESILIENCE-1.",
    },
    "MASVS-CRYPTO-1": {
        "keywords": ["ecb", "md5", "sha1", "des", "rc4"],
        "verdict": "CONFIRMED",
        "justification": "Weak cryptographic algorithm detected. Use of ECB/MD5/SHA1/DES/RC4 is a confirmed vulnerability per MASVS-CRYPTO-1.",
    },
    "MASVS-NETWORK-1": {
        "keywords": ["cleartext", "http://"],
        "verdict": "CONFIRMED",
        "justification": "Cleartext network traffic detected. All communication must use TLS per MASVS-NETWORK-1.",
    },
    "MASVS-STORAGE-1": {
        "keywords": ["allowbackup", "android:allowbackup"],
        "verdict": "CONFIRMED",
        "justification": "Insecure backup configuration detected. android:allowBackup=true exposes app data per MASVS-STORAGE-1.",
    },
}


def rule_based_pre_triage(finding: dict) -> "tuple[str, str] | None":
    """
    Deterministic pre-triage based on known-bad keyword patterns.

    Returns:
        ("CONFIRMED", justification) - finding is a known true positive (bypass LLM).
        ("DISMISSED", justification) - finding is a known false positive (bypass LLM).
        None                         - inconclusive; fall through to LLM triage.
    """
    control = (finding.get("masvs_control") or "").upper()
    rule = _RULE_KEYWORDS.get(control)
    if rule is None:
        return None

    haystack = " ".join([
        (finding.get("title") or ""),
        (finding.get("description") or ""),
    ]).lower()

    for kw in rule["keywords"]:
        if kw in haystack:
            return rule["verdict"], rule["justification"]

    return None


# TRIAGE FUNCTION
# ═══════════════════════════════════════════════════════

def triage_finding(
    finding_id: int,
    title: str,
    severity: str,
    masvs_control: str,
    masvs_description: str,
    description: str = "",
    affected_file: str = "",
    code_context: str = "",
    historical_feedback: str = "",
) -> TriageDecision:
    """
    Use an LLM to triage a single finding.

    Args:
        finding_id: Database ID of the finding.
        title: Finding title.
        severity: Current severity level.
        masvs_control: MASVS control ID (e.g., MASVS-STORAGE-1).
        masvs_description: Human-readable control description.
        description: Finding description.
        affected_file: Path to the affected file.
        code_context: Decompiled code snippet.

    Returns:
        TriageDecision with the LLM's verdict.
    """
    import json

    llm = LLMClient()

    # Build the code context section for the prompt
    if code_context:
        code_section = "Relevant source code:\n```\n" + code_context + "\n```"
    else:
        code_section = (
            "No source code available. Do not dismiss this finding solely due to lack of code. "
            "Set is_true_positive to null and add a note in justification that code context is missing."
        )

    user_prompt = TRIAGE_USER_PROMPT.format(
        title=title,
        severity=severity,
        masvs_control=masvs_control,
        masvs_description=masvs_description,
        affected_file=affected_file or "N/A",
        description=description or "No additional description.",
        code_context=code_section,
        historical_feedback=historical_feedback or "No prior auditor feedback found for similar findings.",
    )

    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            response = llm.chat(
                system_prompt=TRIAGE_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                json_mode=True,
            )

            result = json.loads(response)

            return TriageDecision(
                finding_id=finding_id,
                is_true_positive=result.get("is_true_positive", True),
                confidence=float(result.get("confidence", 0.5)),
                justification=result.get("justification", "No justification provided"),
                suggested_severity=result.get("suggested_severity"),
            )

        except (json.JSONDecodeError, Exception) as e:
            if attempt == max_retries:
                return TriageDecision(
                    finding_id=finding_id,
                    is_true_positive=True,  # Conservative: assume true positive on error
                    confidence=0.0,
                    justification=f"LLM triage failed after {max_retries} retries: {str(e)}. Defaulting to true positive.",
                )
            # Log or print retry status if needed (optional)
            continue


def triage_findings_batch(findings: list) -> List[TriageDecision]:
    """Triage a batch of findings: rules first, then parallel LLM calls."""
    from app.mapping.masvs_mapper import MASVS_CONTROLS
    from concurrent.futures import ThreadPoolExecutor, as_completed

    decisions: List[TriageDecision] = []
    ambiguous: list = []

    # Fast pass: deterministic rules (no LLM, no I/O)
    for f in findings:
        pre = rule_based_pre_triage(f)
        if pre is not None:
            verdict, justification = pre
            decisions.append(TriageDecision(
                finding_id=f.get("id", 0),
                is_true_positive=(verdict == "CONFIRMED"),
                confidence=0.95,
                justification=justification,
            ))
        else:
            ambiguous.append(f)

    if not ambiguous:
        return decisions

    # Slow pass: parallel LLM triage for ambiguous findings
    def _call_triage(f: dict) -> TriageDecision:
        """Worker: calls triage_finding() for one finding in a thread."""
        return triage_finding(
            finding_id=f.get("id", 0),
            title=f.get("title", ""),
            severity=f.get("severity", "info"),
            masvs_control=f.get("masvs_control", ""),
            masvs_description=MASVS_CONTROLS.get(f.get("masvs_control", ""), ""),
            description=f.get("description", ""),
            affected_file=f.get("affected_file", ""),
            code_context=f.get("code_context") or f.get("affected_code", ""),
            historical_feedback=f.get("historical_feedback", ""),
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        futures = {pool.submit(_call_triage, f): f for f in ambiguous}
        for fut in as_completed(futures):
            try:
                decisions.append(fut.result())
            except Exception as e:
                f_dict = futures[fut]
                decisions.append(TriageDecision(
                    finding_id=f_dict.get("id", 0),
                    is_true_positive=True,
                    confidence=0.0,
                    justification="LLM triage failed in thread: " + str(e) + ". Defaulting to true positive.",
                ))

    return decisions
