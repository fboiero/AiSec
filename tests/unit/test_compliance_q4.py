"""Tests for Q4 compliance framework evaluators (EU AI Act, ISO 42001, Argentina AI, NIST 600-1)."""

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.frameworks.compliance.eu_ai_act import evaluate_eu_ai_act
from aisec.frameworks.compliance.iso_42001 import evaluate_iso_42001
from aisec.frameworks.compliance.argentina_ai import evaluate_argentina_ai
from aisec.frameworks.nist_ai_600_1 import evaluate_nist_600_1


# ---------------------------------------------------------------------------
# EU AI Act
# ---------------------------------------------------------------------------


def test_eu_ai_act_evaluate_clean():
    checklist = evaluate_eu_ai_act([], [])
    assert "EU AI Act" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_eu_ai_act_evaluate_with_issues():
    findings = [
        Finding(
            title="Prompt injection vulnerability compromising cybersecurity",
            description="Adversarial attack via data poisoning against the AI system",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM01"],
        )
    ]
    checklist = evaluate_eu_ai_act(findings, [])
    # Should match EUAIA-Art15 (accuracy, robustness, and cybersecurity)
    assert checklist.total_checks > 0
    assert checklist.failed > 0


def test_eu_ai_act_framework_name():
    checklist = evaluate_eu_ai_act([], [])
    assert "EU AI Act" in checklist.framework_name


def test_eu_ai_act_total_checks():
    checklist = evaluate_eu_ai_act([], [])
    assert checklist.total_checks > 0


# ---------------------------------------------------------------------------
# ISO/IEC 42001
# ---------------------------------------------------------------------------


def test_iso_42001_evaluate_clean():
    checklist = evaluate_iso_42001([], [])
    assert "ISO/IEC 42001" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_iso_42001_evaluate_with_issues():
    findings = [
        Finding(
            title="Critical risk assessment failure in AI risk management",
            description="Threat assessment reveals unmitigated AI risk in the system",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM09"],
        )
    ]
    checklist = evaluate_iso_42001(findings, [])
    # Should match ISO42001-6.1 (actions to address risks and opportunities)
    assert checklist.total_checks > 0
    assert checklist.failed > 0


def test_iso_42001_framework_name():
    checklist = evaluate_iso_42001([], [])
    assert "ISO/IEC 42001" in checklist.framework_name


def test_iso_42001_total_checks():
    checklist = evaluate_iso_42001([], [])
    assert checklist.total_checks > 0


# ---------------------------------------------------------------------------
# Argentina AI Governance
# ---------------------------------------------------------------------------


def test_argentina_ai_evaluate_clean():
    checklist = evaluate_argentina_ai([], [])
    assert "Argentina" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_argentina_ai_evaluate_with_issues():
    findings = [
        Finding(
            title="Bias in automated decision-making affecting fairness",
            description="Non-discrimination violation with discriminatory outcomes detected",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM06"],
        )
    ]
    checklist = evaluate_argentina_ai(findings, [])
    # Should match ARGA-3003.Art9 (non-discrimination and fairness)
    # and ARGA-25326-AI.1 (automated decision-making transparency)
    assert checklist.total_checks > 0
    assert checklist.failed > 0


def test_argentina_ai_framework_name():
    checklist = evaluate_argentina_ai([], [])
    assert "Argentina" in checklist.framework_name


def test_argentina_ai_total_checks():
    checklist = evaluate_argentina_ai([], [])
    assert checklist.total_checks > 0


# ---------------------------------------------------------------------------
# NIST AI 600-1 (Generative AI Profile)
# ---------------------------------------------------------------------------


def test_nist_600_1_evaluate_clean():
    checklist = evaluate_nist_600_1([], [])
    assert "NIST AI 600-1" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_nist_600_1_evaluate_with_issues():
    findings = [
        Finding(
            title="Prompt injection attack allows jailbreak of the model",
            description="Adversarial evasion bypasses safety guardrails",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM01"],
        )
    ]
    checklist = evaluate_nist_600_1(findings, [])
    # Should match GAI-8 (information security: prompt injection, adversarial, jailbreak)
    assert checklist.total_checks > 0
    assert checklist.failed > 0


def test_nist_600_1_framework_name():
    checklist = evaluate_nist_600_1([], [])
    assert "NIST AI 600-1" in checklist.framework_name


def test_nist_600_1_total_checks():
    checklist = evaluate_nist_600_1([], [])
    assert checklist.total_checks > 0
