"""Tests for v1.7.0 Falco correlation rules."""

from __future__ import annotations

import pytest

from aisec.core.correlation import CORRELATION_RULES, correlate
from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding


def _make_result(agent: str, findings: list[Finding]) -> AgentResult:
    return AgentResult(agent=agent, findings=findings, duration_seconds=1.0)


class TestFalcoCorrelationRules:
    """Test that v1.7.0 Falco correlation rules are registered."""

    def test_falco_rules_count(self):
        falco_rules = [r for r in CORRELATION_RULES if "Falco" in r["name"]]
        assert len(falco_rules) == 5

    def test_total_rules_count(self):
        assert len(CORRELATION_RULES) >= 31  # 26 from v1.5 + 5 from v1.7


class TestFalcoExploitationCorrelation:
    """Falco Runtime Alert + Open Port = Active Exploitation."""

    def test_fires_when_both_present(self):
        results = {
            "falco_runtime": _make_result("falco_runtime", [
                Finding(title="Falco: Reverse Shell Spawned", severity=Severity.CRITICAL, agent="falco_runtime"),
            ]),
            "network": _make_result("network", [
                Finding(title="Open port 8080 detected", severity=Severity.MEDIUM, agent="network"),
            ]),
        }
        risks = correlate(results)
        matching = [r for r in risks if "Active Exploitation" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_no_fire_without_falco(self):
        results = {
            "network": _make_result("network", [
                Finding(title="Open port 8080 detected", severity=Severity.MEDIUM, agent="network"),
            ]),
        }
        risks = correlate(results)
        matching = [r for r in risks if "Active Exploitation" in r.name]
        assert len(matching) == 0


class TestFalcoModelPoisoningCorrelation:
    """Falco File Tampering + Weak Permissions = Model Poisoning."""

    def test_fires_when_both_present(self):
        results = {
            "falco_runtime": _make_result("falco_runtime", [
                Finding(title="Falco: AI Model File Tampering", severity=Severity.CRITICAL, agent="falco_runtime"),
            ]),
            "permission": _make_result("permission", [
                Finding(title="Model directory writable by all", severity=Severity.HIGH, agent="permission"),
            ]),
        }
        risks = correlate(results)
        matching = [r for r in risks if "Model Poisoning" in r.name]
        assert len(matching) == 1


class TestFalcoCryptojackingCorrelation:
    """Falco Crypto Mining + Resource Exhaustion = Cryptojacking."""

    def test_fires_when_both_present(self):
        results = {
            "falco_runtime": _make_result("falco_runtime", [
                Finding(title="Falco: Cryptocurrency Mining Activity", severity=Severity.CRITICAL, agent="falco_runtime"),
            ]),
            "resource_exhaustion": _make_result("resource_exhaustion", [
                Finding(title="CPU usage anomaly", severity=Severity.HIGH, agent="resource_exhaustion"),
            ]),
        }
        risks = correlate(results)
        matching = [r for r in risks if "Cryptojacking" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL


class TestFalcoContainerEscapeCorrelation:
    """Falco Container Escape + Privileged Mode = Full Compromise."""

    def test_fires_when_both_present(self):
        results = {
            "falco_runtime": _make_result("falco_runtime", [
                Finding(title="Falco: Container Escape Attempt", severity=Severity.CRITICAL, agent="falco_runtime"),
            ]),
            "permission": _make_result("permission", [
                Finding(title="Container runs in privileged mode", severity=Severity.CRITICAL, agent="permission"),
            ]),
        }
        risks = correlate(results)
        matching = [r for r in risks if "Full Compromise" in r.name]
        assert len(matching) == 1
