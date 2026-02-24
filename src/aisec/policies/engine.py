"""Policy evaluation engine for CI/CD gating."""

from __future__ import annotations

import logging
import operator
import re
from typing import Any

from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding
from aisec.policies.models import (
    GateDecision,
    GateVerdict,
    Policy,
    PolicyRule,
    RuleViolation,
)

logger = logging.getLogger(__name__)

# Operator mapping for count expressions like ">5", ">=10", "==0"
_OP_MAP = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

_COUNT_RE = re.compile(r"^(>=|<=|>|<|==|!=)\s*(\d+)$")


class PolicyEngine:
    """Evaluates scan results against a security policy."""

    def evaluate(
        self,
        policy: Policy,
        findings: list[Finding],
        agent_results: list[AgentResult] | None = None,
    ) -> GateDecision:
        """Evaluate findings against a policy and produce a gate decision.

        Args:
            policy: The policy to evaluate against.
            findings: All findings from the scan.
            agent_results: Optional list of agent results for agent-level checks.

        Returns:
            A GateDecision with verdict, violations, and exit code.
        """
        decision = GateDecision(policy_name=policy.name)

        # Count findings by severity and agent
        counts = self._count_findings(findings)

        # Evaluate blocking rules
        for rule in policy.gate.block_on:
            actual = self._get_count(counts, rule)
            if self._rule_triggered(rule, actual):
                decision.violations.append(
                    RuleViolation(
                        rule=rule,
                        actual_count=actual,
                        is_blocking=True,
                        message=self._violation_message(rule, actual, blocking=True),
                    )
                )

        # Evaluate warning rules
        for rule in policy.gate.warn_on:
            actual = self._get_count(counts, rule)
            if self._rule_triggered(rule, actual):
                decision.warnings.append(
                    RuleViolation(
                        rule=rule,
                        actual_count=actual,
                        is_blocking=False,
                        message=self._violation_message(rule, actual, blocking=False),
                    )
                )

        # Check threshold limits
        self._check_thresholds(policy, counts, decision)

        # Check required agents
        if agent_results is not None and policy.required_agents:
            completed_agents = {r.agent for r in agent_results if r.error is None}
            for agent_name in policy.required_agents:
                if agent_name not in completed_agents:
                    decision.missing_agents.append(agent_name)

        # Determine verdict
        if decision.violations or decision.missing_agents:
            decision.verdict = GateVerdict.FAIL
            decision.exit_code = 1
        elif decision.warnings:
            decision.verdict = GateVerdict.WARN
            decision.exit_code = 2
        else:
            decision.verdict = GateVerdict.PASS
            decision.exit_code = 0

        decision.summary = self._build_summary(decision, len(findings))
        logger.info("Policy %s: %s (exit code %d)", policy.name, decision.verdict.value, decision.exit_code)
        return decision

    def _count_findings(self, findings: list[Finding]) -> dict[str, Any]:
        """Count findings by severity and by (agent, severity) pairs."""
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_agent_severity: dict[tuple[str, str], int] = {}

        for f in findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            key = (f.agent, sev)
            by_agent_severity[key] = by_agent_severity.get(key, 0) + 1

        return {
            "by_severity": by_severity,
            "by_agent_severity": by_agent_severity,
            "total": len(findings),
        }

    def _get_count(self, counts: dict[str, Any], rule: PolicyRule) -> int:
        """Get the relevant count for a rule."""
        if rule.agent and rule.severity:
            return counts["by_agent_severity"].get((rule.agent, rule.severity), 0)
        elif rule.severity:
            return counts["by_severity"].get(rule.severity, 0)
        elif rule.agent:
            return sum(
                v for (a, _), v in counts["by_agent_severity"].items()
                if a == rule.agent
            )
        return counts["total"]

    def _rule_triggered(self, rule: PolicyRule, actual: int) -> bool:
        """Check if a rule's count condition is met."""
        match = _COUNT_RE.match(rule.count.strip())
        if not match:
            # Default: treat as ">0"
            return actual > 0

        op_str, threshold_str = match.groups()
        op_fn = _OP_MAP.get(op_str, operator.gt)
        threshold = int(threshold_str)
        return op_fn(actual, threshold)

    def _check_thresholds(
        self, policy: Policy, counts: dict[str, Any], decision: GateDecision
    ) -> None:
        """Check numeric threshold limits."""
        t = policy.thresholds
        by_sev = counts["by_severity"]

        checks = [
            ("max_critical", t.max_critical, "critical"),
            ("max_high", t.max_high, "high"),
            ("max_medium", t.max_medium, "medium"),
        ]

        for name, limit, severity in checks:
            if limit < 0:
                continue  # unlimited
            actual = by_sev.get(severity, 0)
            if actual > limit:
                decision.violations.append(
                    RuleViolation(
                        rule=PolicyRule(severity=severity, count=f"<={limit}"),
                        actual_count=actual,
                        is_blocking=True,
                        message=f"Threshold exceeded: {actual} {severity} findings (max {limit})",
                    )
                )

    def _violation_message(self, rule: PolicyRule, actual: int, blocking: bool) -> str:
        """Build a human-readable violation message."""
        prefix = "BLOCKED" if blocking else "WARNING"
        agent_part = f" from agent '{rule.agent}'" if rule.agent else ""
        return (
            f"[{prefix}] {actual} {rule.severity or 'total'} finding(s){agent_part} "
            f"(threshold: {rule.count})"
        )

    def _build_summary(self, decision: GateDecision, total_findings: int) -> str:
        """Build a summary string for the gate decision."""
        parts = [f"Policy '{decision.policy_name}': {decision.verdict.value.upper()}"]
        parts.append(f"{total_findings} total findings")

        if decision.violations:
            parts.append(f"{len(decision.violations)} blocking violation(s)")
        if decision.warnings:
            parts.append(f"{len(decision.warnings)} warning(s)")
        if decision.missing_agents:
            parts.append(f"{len(decision.missing_agents)} required agent(s) missing")

        return " | ".join(parts)
