"""Tests for the policy-as-code engine."""

from __future__ import annotations

import pytest

from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding
from aisec.policies.engine import PolicyEngine
from aisec.policies.loader import load_policy
from aisec.policies.models import (
    GateDecision,
    GateVerdict,
    Policy,
    PolicyCompliance,
    PolicyGate,
    PolicyRule,
    PolicyThresholds,
    RuleViolation,
)


class TestPolicyModels:
    """Test policy data models."""

    def test_policy_defaults(self):
        p = Policy()
        assert p.name == ""
        assert p.version == "1.0"

    def test_gate_verdict_values(self):
        assert GateVerdict.PASS.value == "pass"
        assert GateVerdict.FAIL.value == "fail"
        assert GateVerdict.WARN.value == "warn"

    def test_gate_decision_defaults(self):
        d = GateDecision()
        assert d.verdict == GateVerdict.PASS
        assert d.exit_code == 0


class TestPolicyLoader:
    """Test YAML policy loading."""

    def test_load_strict(self):
        policy = load_policy("strict")
        assert policy.name == "strict"
        assert len(policy.gate.block_on) >= 2
        assert policy.thresholds.max_critical == 0
        assert policy.thresholds.max_high == 0
        assert len(policy.required_agents) >= 20

    def test_load_moderate(self):
        policy = load_policy("moderate")
        assert policy.name == "moderate"
        assert policy.thresholds.max_high == 5

    def test_load_permissive(self):
        policy = load_policy("permissive")
        assert policy.name == "permissive"
        assert policy.thresholds.max_critical == 2

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy("nonexistent_policy_xyz")


class TestPolicyEngine:
    """Test policy evaluation."""

    def _make_findings(self, critical=0, high=0, medium=0, low=0):
        findings = []
        for _ in range(critical):
            findings.append(Finding(title="Critical issue", severity=Severity.CRITICAL, agent="test"))
        for _ in range(high):
            findings.append(Finding(title="High issue", severity=Severity.HIGH, agent="test"))
        for _ in range(medium):
            findings.append(Finding(title="Medium issue", severity=Severity.MEDIUM, agent="test"))
        for _ in range(low):
            findings.append(Finding(title="Low issue", severity=Severity.LOW, agent="test"))
        return findings

    def test_pass_with_no_findings(self):
        engine = PolicyEngine()
        policy = load_policy("strict")
        decision = engine.evaluate(policy, [])
        assert decision.verdict == GateVerdict.PASS
        assert decision.exit_code == 0

    def test_strict_fails_on_critical(self):
        engine = PolicyEngine()
        policy = load_policy("strict")
        findings = self._make_findings(critical=1)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL
        assert decision.exit_code == 1

    def test_strict_fails_on_high(self):
        engine = PolicyEngine()
        policy = load_policy("strict")
        findings = self._make_findings(high=1)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL
        assert decision.exit_code == 1

    def test_moderate_passes_low_high(self):
        engine = PolicyEngine()
        policy = load_policy("moderate")
        findings = self._make_findings(high=3)
        decision = engine.evaluate(policy, findings)
        # moderate allows up to 5 high
        assert decision.exit_code != 1 or len(decision.violations) == 0

    def test_moderate_fails_on_critical(self):
        engine = PolicyEngine()
        policy = load_policy("moderate")
        findings = self._make_findings(critical=1)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL

    def test_permissive_warns_on_critical(self):
        engine = PolicyEngine()
        policy = load_policy("permissive")
        findings = self._make_findings(critical=1)
        decision = engine.evaluate(policy, findings)
        # permissive allows up to 2 critical, but warns on >0
        assert decision.verdict == GateVerdict.WARN
        assert decision.exit_code == 2

    def test_permissive_fails_on_many_critical(self):
        engine = PolicyEngine()
        policy = load_policy("permissive")
        findings = self._make_findings(critical=3)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL
        assert decision.exit_code == 1

    def test_summary_includes_policy_name(self):
        engine = PolicyEngine()
        policy = load_policy("strict")
        decision = engine.evaluate(policy, [])
        assert "strict" in decision.summary

    def test_missing_agents_detected(self):
        engine = PolicyEngine()
        policy = load_policy("strict")
        agent_results = [AgentResult(agent="network", findings=[])]
        decision = engine.evaluate(policy, [], agent_results=agent_results)
        assert len(decision.missing_agents) > 0

    def test_custom_policy(self):
        engine = PolicyEngine()
        policy = Policy(
            name="custom",
            gate=PolicyGate(
                block_on=[PolicyRule(severity="critical", count=">0")],
            ),
            thresholds=PolicyThresholds(max_critical=0),
        )
        findings = self._make_findings(critical=1)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL

    def test_agent_specific_rule(self):
        engine = PolicyEngine()
        policy = Policy(
            name="agent-specific",
            gate=PolicyGate(
                block_on=[PolicyRule(severity="high", count=">0", agent="mcp_security")],
            ),
        )
        findings = [
            Finding(title="MCP issue", severity=Severity.HIGH, agent="mcp_security"),
        ]
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL

    def test_agent_specific_rule_other_agent_passes(self):
        engine = PolicyEngine()
        policy = Policy(
            name="agent-specific",
            gate=PolicyGate(
                block_on=[PolicyRule(severity="high", count=">0", agent="mcp_security")],
            ),
        )
        findings = [
            Finding(title="Some issue", severity=Severity.HIGH, agent="network"),
        ]
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.PASS

    def test_threshold_violation(self):
        engine = PolicyEngine()
        policy = Policy(
            name="threshold",
            thresholds=PolicyThresholds(max_medium=5),
        )
        findings = self._make_findings(medium=10)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.FAIL

    def test_threshold_within_limit(self):
        engine = PolicyEngine()
        policy = Policy(
            name="threshold",
            thresholds=PolicyThresholds(max_medium=10),
        )
        findings = self._make_findings(medium=5)
        decision = engine.evaluate(policy, findings)
        assert decision.verdict == GateVerdict.PASS
