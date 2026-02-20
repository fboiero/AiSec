"""Tests for AI-CVSS risk scoring."""

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.reports.scoring import AiCvssScore, compute_risk_overview, score_finding


def test_ai_cvss_score_default():
    score = AiCvssScore()
    result = score.compute_score()
    assert 0.0 <= result <= 10.0


def test_ai_cvss_score_high_risk():
    score = AiCvssScore(
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        autonomy_impact=0.9,
        data_sensitivity=0.9,
        tool_access_scope=0.9,
        persistence_risk=0.8,
        cascade_potential=0.8,
    )
    result = score.compute_score()
    assert result >= 7.0


def test_ai_cvss_score_low_risk():
    score = AiCvssScore(
        attack_vector="physical",
        attack_complexity="high",
        privileges_required="high",
        user_interaction="required",
        autonomy_impact=0.1,
        data_sensitivity=0.1,
        tool_access_scope=0.1,
        persistence_risk=0.1,
        cascade_potential=0.1,
    )
    result = score.compute_score()
    assert result <= 3.0


def test_score_finding_critical():
    f = Finding(severity=Severity.CRITICAL, owasp_llm=["LLM01"], owasp_agentic=["ASI01"])
    score = score_finding(f)
    assert score >= 9.0


def test_score_finding_info():
    f = Finding(severity=Severity.INFO)
    score = score_finding(f)
    assert score <= 2.0


def test_compute_risk_overview_empty():
    overview = compute_risk_overview([])
    assert overview.ai_risk_score == 0.0


def test_compute_risk_overview(sample_findings):
    overview = compute_risk_overview(sample_findings)
    assert overview.ai_risk_score > 0
    assert overview.attack_surface_score >= 0
    assert overview.data_exposure_score >= 0
    assert overview.agency_risk_score >= 0
    assert overview.supply_chain_score >= 0
