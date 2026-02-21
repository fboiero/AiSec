"""Tests for compliance framework evaluators."""

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.frameworks.compliance.gdpr import evaluate_gdpr
from aisec.frameworks.compliance.ccpa import evaluate_ccpa
from aisec.frameworks.compliance.habeas_data import evaluate_habeas_data


def test_gdpr_evaluate_clean():
    checklist = evaluate_gdpr([], [])
    assert "GDPR" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_gdpr_evaluate_with_data_disclosure():
    findings = [
        Finding(
            title="Data breach with unauthorised access to personal data",
            description="Sensitive data exposure detected",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM02"],
        )
    ]
    checklist = evaluate_gdpr(findings, [])
    # Should match Art 5.1.f (integrity/confidentiality) or Art 32 (security)
    assert checklist.total_checks > 0


def test_ccpa_evaluate_clean():
    checklist = evaluate_ccpa([], [])
    assert "CCPA" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_ccpa_evaluate_with_breach():
    findings = [
        Finding(
            title="Data breach exposing personal information",
            description="Unauthorised access to data exposure detected",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM02"],
        )
    ]
    checklist = evaluate_ccpa(findings, [])
    assert checklist.failed > 0


def test_habeas_data_evaluate_clean():
    checklist = evaluate_habeas_data([], [])
    assert "Habeas Data" in checklist.framework_name or "25.326" in checklist.framework_name
    assert checklist.total_checks > 0
    assert checklist.failed == 0


def test_habeas_data_evaluate_with_issues():
    findings = [
        Finding(
            title="Data security breach with unauthorised access",
            description="Encryption and access control failures detected",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI02"],
        )
    ]
    checklist = evaluate_habeas_data(findings, [])
    assert checklist.failed > 0
