"""AI-enhanced CVSS risk scoring engine."""

from __future__ import annotations

from dataclasses import dataclass
from aisec.core.enums import Severity
from aisec.core.models import Finding, RiskOverview


@dataclass
class AiCvssScore:
    """AI-enhanced CVSS scoring with AI-specific risk dimensions."""

    # Standard CVSS base metrics (simplified)
    attack_vector: str = "network"  # network, adjacent, local, physical
    attack_complexity: str = "low"  # low, high
    privileges_required: str = "none"  # none, low, high
    user_interaction: str = "none"  # none, required

    # AI-specific dimensions (0.0-1.0)
    autonomy_impact: float = 0.5
    data_sensitivity: float = 0.5
    tool_access_scope: float = 0.5
    persistence_risk: float = 0.3
    cascade_potential: float = 0.3

    def compute_score(self) -> float:
        """Compute composite AI-CVSS score (0.0-10.0)."""
        av_scores = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
        ac_scores = {"low": 0.77, "high": 0.44}
        pr_scores = {"none": 0.85, "low": 0.62, "high": 0.27}
        ui_scores = {"none": 0.85, "required": 0.62}

        base = (
            av_scores.get(self.attack_vector, 0.5)
            * ac_scores.get(self.attack_complexity, 0.5)
            * pr_scores.get(self.privileges_required, 0.5)
            * ui_scores.get(self.user_interaction, 0.5)
        ) * 10.0

        ai_modifier = (
            self.autonomy_impact * 0.25
            + self.data_sensitivity * 0.20
            + self.tool_access_scope * 0.25
            + self.persistence_risk * 0.15
            + self.cascade_potential * 0.15
        )

        return min(10.0, round(base + ai_modifier * 3.0, 1))


def score_finding(finding: Finding) -> float:
    """Compute an AI-CVSS score for a finding based on its properties."""
    severity_base = {
        Severity.CRITICAL: 9.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
    }
    base = severity_base.get(finding.severity, 5.0)

    # Adjust based on framework mappings breadth
    mapping_count = len(finding.owasp_llm) + len(finding.owasp_agentic) + len(finding.nist_ai_rmf)
    breadth_modifier = min(1.0, mapping_count * 0.15)

    return min(10.0, round(base + breadth_modifier, 1))


def compute_risk_overview(findings: list[Finding]) -> RiskOverview:
    """Compute composite risk overview from all findings."""
    if not findings:
        return RiskOverview()

    attack_surface_ids = {"LLM01", "LLM09", "ASI01", "ASI07", "ASI08"}
    data_exposure_ids = {"LLM02", "LLM07", "ASI06"}
    agency_ids = {"LLM06", "ASI02", "ASI03", "ASI10"}
    supply_chain_ids = {"LLM03", "LLM04", "ASI04", "ASI05"}

    def _dimension_score(target_ids: set[str]) -> float:
        relevant = [
            f for f in findings
            if target_ids & (set(f.owasp_llm) | set(f.owasp_agentic))
        ]
        if not relevant:
            return 0.0
        severity_weights = {
            Severity.CRITICAL: 100, Severity.HIGH: 75,
            Severity.MEDIUM: 50, Severity.LOW: 25, Severity.INFO: 10,
        }
        total = sum(severity_weights.get(f.severity, 10) for f in relevant)
        return min(100.0, total)

    scores = [score_finding(f) for f in findings]
    ai_risk = round(sum(scores) / len(scores) * 10, 1) if scores else 0.0

    return RiskOverview(
        ai_risk_score=min(100.0, ai_risk),
        attack_surface_score=_dimension_score(attack_surface_ids),
        data_exposure_score=_dimension_score(data_exposure_ids),
        agency_risk_score=_dimension_score(agency_ids),
        supply_chain_score=_dimension_score(supply_chain_ids),
        compliance_score=0.0,  # filled by compliance evaluators
    )
