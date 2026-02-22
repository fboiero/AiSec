"""Tests for the cross-agent correlation engine."""

from __future__ import annotations

import pytest

from aisec.core.correlation import (
    CORRELATION_RULES,
    CorrelatedRisk,
    correlate,
    _check_condition,
)
from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Evidence, Finding


class TestCorrelationRules:
    """Test correlation rule definitions."""

    def test_rules_populated(self):
        assert len(CORRELATION_RULES) >= 5

    def test_rule_structure(self):
        for rule in CORRELATION_RULES:
            assert "name" in rule
            assert "conditions" in rule
            assert "severity" in rule
            assert "description" in rule
            assert "remediation" in rule
            assert isinstance(rule["conditions"], list)
            assert len(rule["conditions"]) >= 2

    def test_rule_conditions_have_agent(self):
        for rule in CORRELATION_RULES:
            for cond in rule["conditions"]:
                assert "agent" in cond


class TestCheckCondition:
    """Test individual condition matching."""

    def test_title_contains_match(self):
        findings = [
            Finding(
                title="Hardcoded credential found",
                severity=Severity.HIGH,
                agent="dataflow",
            )
        ]
        condition = {
            "agent": "dataflow",
            "title_contains": "credential",
            "any_title": True,
        }
        result = _check_condition(condition, {"dataflow": findings})
        assert len(result) == 1

    def test_title_contains_no_match(self):
        findings = [
            Finding(
                title="PII in logs",
                severity=Severity.MEDIUM,
                agent="dataflow",
            )
        ]
        condition = {
            "agent": "dataflow",
            "title_contains": "credential",
            "any_title": True,
        }
        result = _check_condition(condition, {"dataflow": findings})
        assert len(result) == 0

    def test_severity_gte_match(self):
        findings = [
            Finding(
                title="Root container",
                severity=Severity.HIGH,
                agent="permission",
            )
        ]
        condition = {
            "agent": "permission",
            "severity_gte": Severity.MEDIUM,
        }
        result = _check_condition(condition, {"permission": findings})
        assert len(result) == 1

    def test_severity_gte_no_match(self):
        findings = [
            Finding(
                title="Info finding",
                severity=Severity.INFO,
                agent="permission",
            )
        ]
        condition = {
            "agent": "permission",
            "severity_gte": Severity.MEDIUM,
        }
        result = _check_condition(condition, {"permission": findings})
        assert len(result) == 0

    def test_finding_count_eq_zero(self):
        condition = {
            "agent": "sbom",
            "finding_count_eq": 0,
        }
        # Agent has no findings
        result = _check_condition(condition, {"sbom": []})
        assert result == []  # Condition met but no findings

    def test_missing_agent(self):
        condition = {
            "agent": "nonexistent",
            "title_contains": "anything",
            "any_title": True,
        }
        result = _check_condition(condition, {})
        assert len(result) == 0


class TestCorrelate:
    """Test the full correlation engine."""

    def test_no_agent_results(self):
        risks = correlate({})
        assert len(risks) == 0

    def test_single_agent_no_correlation(self):
        results = {
            "dataflow": AgentResult(
                agent="dataflow",
                findings=[
                    Finding(
                        title="Hardcoded credential found",
                        severity=Severity.HIGH,
                        agent="dataflow",
                    )
                ],
            ),
        }
        risks = correlate(results)
        # Should not correlate with just one agent
        credential_risks = [r for r in risks if "credential" in r.name.lower()]
        # The specific "Exposed Secret + Open Port" rule needs BOTH agents
        exposed_risks = [r for r in risks if "Exposed Secret" in r.name]
        assert len(exposed_risks) == 0

    def test_credential_plus_port_correlation(self):
        results = {
            "dataflow": AgentResult(
                agent="dataflow",
                findings=[
                    Finding(
                        title="Hardcoded credential found in config",
                        severity=Severity.HIGH,
                        agent="dataflow",
                    )
                ],
            ),
            "network": AgentResult(
                agent="network",
                findings=[
                    Finding(
                        title="Open port 8080 detected",
                        severity=Severity.MEDIUM,
                        agent="network",
                    )
                ],
            ),
        }
        risks = correlate(results)

        leak_risks = [r for r in risks if "Data Leak" in r.name]
        assert len(leak_risks) == 1
        assert leak_risks[0].severity == Severity.CRITICAL
        assert "dataflow" in leak_risks[0].agents_involved
        assert "network" in leak_risks[0].agents_involved

    def test_no_validation_plus_no_guardrails(self):
        results = {
            "prompt_security": AgentResult(
                agent="prompt_security",
                findings=[
                    Finding(
                        title="No input validation detected",
                        severity=Severity.HIGH,
                        agent="prompt_security",
                    )
                ],
            ),
            "guardrails": AgentResult(
                agent="guardrails",
                findings=[
                    Finding(
                        title="No guardrail framework detected",
                        severity=Severity.HIGH,
                        agent="guardrails",
                    )
                ],
            ),
        }
        risks = correlate(results)

        injection_risks = [r for r in risks if "Prompt Injection" in r.name]
        assert len(injection_risks) == 1
        assert injection_risks[0].severity == Severity.CRITICAL

    def test_supply_chain_plus_no_sbom(self):
        results = {
            "supply_chain": AgentResult(
                agent="supply_chain",
                findings=[
                    Finding(
                        title="Unpinned dependencies",
                        severity=Severity.MEDIUM,
                        agent="supply_chain",
                    )
                ],
            ),
            "sbom": AgentResult(
                agent="sbom",
                findings=[],  # No SBOM findings = no SBOM generated
            ),
        }
        risks = correlate(results)

        sbom_risks = [r for r in risks if "Unverifiable" in r.name]
        assert len(sbom_risks) == 1
        assert sbom_risks[0].severity == Severity.HIGH

    def test_correlated_risk_structure(self):
        results = {
            "dataflow": AgentResult(
                agent="dataflow",
                findings=[
                    Finding(
                        title="Hardcoded credential in source",
                        severity=Severity.HIGH,
                        agent="dataflow",
                    )
                ],
            ),
            "network": AgentResult(
                agent="network",
                findings=[
                    Finding(
                        title="Open port 443",
                        severity=Severity.MEDIUM,
                        agent="network",
                    )
                ],
            ),
        }
        risks = correlate(results)

        if risks:
            risk = risks[0]
            assert isinstance(risk, CorrelatedRisk)
            assert risk.name
            assert risk.description
            assert isinstance(risk.severity, Severity)
            assert isinstance(risk.agents_involved, list)
            assert risk.remediation

    def test_multiple_correlations(self):
        results = {
            "dataflow": AgentResult(
                agent="dataflow",
                findings=[
                    Finding(
                        title="Hardcoded credential in config",
                        severity=Severity.HIGH,
                        agent="dataflow",
                    )
                ],
            ),
            "network": AgentResult(
                agent="network",
                findings=[
                    Finding(
                        title="Open port 8080 detected",
                        severity=Severity.MEDIUM,
                        agent="network",
                    )
                ],
            ),
            "prompt_security": AgentResult(
                agent="prompt_security",
                findings=[
                    Finding(
                        title="No input validation detected",
                        severity=Severity.HIGH,
                        agent="prompt_security",
                    )
                ],
            ),
            "guardrails": AgentResult(
                agent="guardrails",
                findings=[
                    Finding(
                        title="No guardrail framework detected",
                        severity=Severity.HIGH,
                        agent="guardrails",
                    )
                ],
            ),
        }
        risks = correlate(results)

        # Should find at least 2 correlations
        assert len(risks) >= 2

    def test_no_correlation_when_conditions_not_met(self):
        results = {
            "dataflow": AgentResult(
                agent="dataflow",
                findings=[
                    Finding(
                        title="PII in logs",  # Not "credential"
                        severity=Severity.MEDIUM,
                        agent="dataflow",
                    )
                ],
            ),
            "network": AgentResult(
                agent="network",
                findings=[
                    Finding(
                        title="DNS resolution working",  # Not "port"
                        severity=Severity.INFO,
                        agent="network",
                    )
                ],
            ),
        }
        risks = correlate(results)

        leak_risks = [r for r in risks if "Data Leak" in r.name]
        assert len(leak_risks) == 0
