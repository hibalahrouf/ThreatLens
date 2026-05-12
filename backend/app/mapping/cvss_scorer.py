"""
MASVS Audit Copilot — CVSS v3.1 Scorer
Calculates CVSS vectors and scores for each finding.
Also computes the global application security score.
"""

from dataclasses import dataclass
from typing import Optional, List

from app.mapping.masvs_mapper import MappedFinding


# ═══════════════════════════════════════════════════════
# CVSS v3.1 BASE METRICS
# ═══════════════════════════════════════════════════════

# Attack Vector (AV)
AV_NETWORK = "N"
AV_ADJACENT = "A"
AV_LOCAL = "L"
AV_PHYSICAL = "P"

# Attack Complexity (AC)
AC_LOW = "L"
AC_HIGH = "H"

# Privileges Required (PR)
PR_NONE = "N"
PR_LOW = "L"
PR_HIGH = "H"

# User Interaction (UI)
UI_NONE = "N"
UI_REQUIRED = "R"

# Scope (S)
S_UNCHANGED = "U"
S_CHANGED = "C"

# CIA Impact
IMPACT_HIGH = "H"
IMPACT_LOW = "L"
IMPACT_NONE = "N"


@dataclass
class CVSSVector:
    """CVSS v3.1 base score vector."""
    attack_vector: str = AV_LOCAL
    attack_complexity: str = AC_LOW
    privileges_required: str = PR_NONE
    user_interaction: str = UI_NONE
    scope: str = S_UNCHANGED
    confidentiality: str = IMPACT_LOW
    integrity: str = IMPACT_NONE
    availability: str = IMPACT_NONE

    def to_string(self) -> str:
        """Generate the CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}"
            f"/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}"
            f"/UI:{self.user_interaction}"
            f"/S:{self.scope}"
            f"/C:{self.confidentiality}"
            f"/I:{self.integrity}"
            f"/A:{self.availability}"
        )

    def calculate_score(self) -> float:
        """
        Calculate the CVSS v3.1 base score.

        Implements the official CVSS v3.1 formula from
        https://www.first.org/cvss/specification-document
        """
        import math

        # Metric value tables
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_values_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_values = {"N": 0.85, "R": 0.62}
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}

        # Exploitability
        pr_table = pr_values_changed if self.scope == "C" else pr_values_unchanged
        exploitability = (
            8.22
            * av_values.get(self.attack_vector, 0.55)
            * ac_values.get(self.attack_complexity, 0.77)
            * pr_table.get(self.privileges_required, 0.85)
            * ui_values.get(self.user_interaction, 0.85)
        )

        # Impact Sub Score (ISS)
        iss = 1 - (
            (1 - impact_values.get(self.confidentiality, 0))
            * (1 - impact_values.get(self.integrity, 0))
            * (1 - impact_values.get(self.availability, 0))
        )

        # Impact
        if self.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Base Score
        if impact <= 0:
            return 0.0

        if self.scope == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        # Round up to one decimal
        return math.ceil(base * 10) / 10


# ═══════════════════════════════════════════════════════
# FINDING → CVSS VECTOR TEMPLATES
# ═══════════════════════════════════════════════════════

# Default CVSS vectors per MASVS control
CONTROL_CVSS_TEMPLATES = {
    "MASVS-STORAGE-1": CVSSVector(AV_LOCAL, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_NONE, IMPACT_NONE),
    "MASVS-STORAGE-2": CVSSVector(AV_LOCAL, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_NONE, IMPACT_NONE),
    "MASVS-CRYPTO-1": CVSSVector(AV_NETWORK, AC_HIGH, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_NONE, IMPACT_NONE),
    "MASVS-CRYPTO-2": CVSSVector(AV_NETWORK, AC_HIGH, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-AUTH-1": CVSSVector(AV_NETWORK, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-AUTH-2": CVSSVector(AV_NETWORK, AC_LOW, PR_NONE, UI_REQUIRED, S_UNCHANGED, IMPACT_HIGH, IMPACT_LOW, IMPACT_NONE),
    "MASVS-AUTH-3": CVSSVector(AV_NETWORK, AC_LOW, PR_LOW, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-NETWORK-1": CVSSVector(AV_NETWORK, AC_HIGH, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-NETWORK-2": CVSSVector(AV_NETWORK, AC_HIGH, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-PLATFORM-1": CVSSVector(AV_LOCAL, AC_LOW, PR_NONE, UI_NONE, S_CHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-PLATFORM-2": CVSSVector(AV_NETWORK, AC_LOW, PR_NONE, UI_REQUIRED, S_CHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-PLATFORM-3": CVSSVector(AV_LOCAL, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_LOW, IMPACT_NONE),
    "MASVS-CODE-1": CVSSVector(AV_NETWORK, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_HIGH),
    "MASVS-CODE-2": CVSSVector(AV_LOCAL, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_LOW, IMPACT_NONE),
    "MASVS-CODE-3": CVSSVector(AV_NETWORK, AC_LOW, PR_NONE, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_HIGH, IMPACT_NONE),
    "MASVS-CODE-4": CVSSVector(AV_LOCAL, AC_HIGH, PR_LOW, UI_NONE, S_UNCHANGED, IMPACT_HIGH, IMPACT_NONE, IMPACT_NONE),
    "MASVS-RESILIENCE-1": CVSSVector(AV_LOCAL, AC_HIGH, PR_HIGH, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_NONE, IMPACT_NONE),
    "MASVS-RESILIENCE-2": CVSSVector(AV_LOCAL, AC_HIGH, PR_HIGH, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_NONE, IMPACT_NONE),
    "MASVS-RESILIENCE-3": CVSSVector(AV_LOCAL, AC_HIGH, PR_HIGH, UI_NONE, S_UNCHANGED, IMPACT_LOW, IMPACT_LOW, IMPACT_NONE),
    "MASVS-RESILIENCE-4": CVSSVector(AV_LOCAL, AC_HIGH, PR_HIGH, UI_NONE, S_UNCHANGED, IMPACT_NONE, IMPACT_LOW, IMPACT_NONE),
}

# Severity escalation adjustments
SEVERITY_ADJUSTMENTS = {
    "critical": {"confidentiality": IMPACT_HIGH, "integrity": IMPACT_HIGH, "availability": IMPACT_HIGH},
    "high": {"confidentiality": IMPACT_HIGH, "integrity": IMPACT_LOW},
    "medium": {},
    "low": {"attack_complexity": AC_HIGH},
    "info": {"attack_complexity": AC_HIGH, "confidentiality": IMPACT_NONE, "integrity": IMPACT_NONE},
}


# ═══════════════════════════════════════════════════════
# SCORING FUNCTIONS
# ═══════════════════════════════════════════════════════

@dataclass
class ScoredFinding:
    """A finding with its CVSS score and vector."""
    finding: MappedFinding
    cvss_vector: str
    cvss_score: float


def score_finding(finding: MappedFinding) -> ScoredFinding:
    """
    Assign a CVSS v3.1 vector and score to a single finding.
    """
    # Get template vector for the MASVS control
    template = CONTROL_CVSS_TEMPLATES.get(
        finding.masvs_control,
        CVSSVector()  # Default conservative vector
    )

    # Create a copy with severity adjustments
    vector = CVSSVector(
        attack_vector=template.attack_vector,
        attack_complexity=template.attack_complexity,
        privileges_required=template.privileges_required,
        user_interaction=template.user_interaction,
        scope=template.scope,
        confidentiality=template.confidentiality,
        integrity=template.integrity,
        availability=template.availability,
    )

    # Apply severity-based adjustments
    adjustments = SEVERITY_ADJUSTMENTS.get(finding.severity, {})
    for attr, value in adjustments.items():
        setattr(vector, attr, value)

    return ScoredFinding(
        finding=finding,
        cvss_vector=vector.to_string(),
        cvss_score=vector.calculate_score(),
    )


def score_findings(findings: List[MappedFinding]) -> List[ScoredFinding]:
    """Score all findings in a scan."""
    return [score_finding(f) for f in findings]


def calculate_global_score(scored_findings: List[ScoredFinding]) -> float:
    """
    Calculate the global application security score (0-100).

    Algorithm (CVSS-weighted average):
    - If no confirmed findings exist, return 100.
    - Collect all non-zero CVSS scores from confirmed findings.
    - Compute the average CVSS score (0-10 scale).
    - Map the average CVSS to a penalty: penalty = min(avg_cvss * 10, 60).
      The cap at 60 ensures that only the most extreme cases reach 0/100.
    - Final score = max(0, 100 - penalty), rounded to 1 decimal.

    Fallback: if no CVSS data is available (all zeros), use the legacy
    severity-based penalty (critical=-15, high=-10, medium=-5, low=-1).
    """
    if not scored_findings:
        return 100.0

    cvss_scores = [
        sf.cvss_score for sf in scored_findings
        if sf.cvss_score and sf.cvss_score > 0
    ]

    if not cvss_scores:
        # Fallback to severity-based penalty when CVSS data is missing
        score = 100.0
        for sf in scored_findings:
            severity = sf.finding.severity
            if severity == "critical":
                score -= 15
            elif severity == "high":
                score -= 10
            elif severity == "medium":
                score -= 5
            elif severity == "low":
                score -= 1
        return round(max(0.0, score), 1)

    avg_cvss = sum(cvss_scores) / len(cvss_scores)
    # CVSS 0-10 maps to penalty 0-60 (cap prevents always hitting 0)
    penalty = min(avg_cvss * 10, 60)
    return round(max(0.0, 100.0 - penalty), 1)


def calculate_grade(score: float) -> str:
    """Convert numeric score to letter grade."""
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"
