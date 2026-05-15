"""Tests for agent-on-agent correlation rules."""

from __future__ import annotations

from aisec.core.correlation import CORRELATION_RULES, correlate
from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding


def _result(agent: str, *findings: Finding) -> AgentResult:
    return AgentResult(agent=agent, findings=list(findings), duration_seconds=1.0)


def _finding(agent: str, title: str, severity: Severity) -> Finding:
    return Finding(agent=agent, title=title, severity=severity)


class TestAgenticReviewCorrelationRules:
    def test_agentic_review_rules_registered(self):
        names = {rule["name"] for rule in CORRELATION_RULES}

        assert "Unbounded Agent Delegation + Dangerous Tools = Autonomous Tool Abuse" in names
        assert "Self-Review + Memory Risk = Persistent Agent Misjudgment" in names
        assert "Unaudited Agent Review + Cascade Risk = Untraceable Multi-Agent Failure" in names
        assert "Agent Handoff Injection + Weak Prompt Defenses = Cross-Agent Prompt Injection" in names
        assert "Reviewer Tool Sharing + Tool Chain Risk = Compromised Control Plane" in names
        assert "Shared Agent Identity + Exposed Credentials = Unattributable Agent Compromise" in names
        assert "High-Impact Agent Action + Privileged Runtime = Unchecked Production Change" in names
        assert "Shared Review Memory + Memory Risk = Biased Agent Oversight" in names
        assert "Suppressed Review Dissent + Cascade Risk = Silent Multi-Agent Failure" in names

    def test_unbounded_delegation_plus_dangerous_tools(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent delegation lacks recursion or budget guard",
                        Severity.HIGH,
                    ),
                ),
                "tool_chain": _result(
                    "tool_chain",
                    _finding(
                        "tool_chain",
                        "Code execution tool without sandbox",
                        Severity.HIGH,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Autonomous Tool Abuse" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL
        assert matching[0].agents_involved == ["agentic_review", "tool_chain"]

    def test_self_review_plus_memory_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent review lacks independent reviewer boundary",
                        Severity.MEDIUM,
                    ),
                ),
                "agent_memory": _result(
                    "agent_memory",
                    _finding(
                        "agent_memory",
                        "Memory poisoning vector detected",
                        Severity.MEDIUM,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Persistent Agent Misjudgment" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.HIGH

    def test_unaudited_review_plus_cascade_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent review decision lacks audit trail",
                        Severity.MEDIUM,
                    ),
                ),
                "cascade": _result(
                    "cascade",
                    _finding(
                        "cascade",
                        "Cascade failure risk without fallback",
                        Severity.MEDIUM,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Untraceable Multi-Agent Failure" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.HIGH

    def test_agentic_review_correlation_does_not_fire_with_single_agent(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent delegation lacks recursion or budget guard",
                        Severity.HIGH,
                    ),
                ),
            }
        )

        assert not [r for r in risks if "Autonomous Tool Abuse" in r.name]

    def test_agent_handoff_injection_plus_prompt_security_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent output is reused as downstream instructions without sanitization",
                        Severity.HIGH,
                    ),
                ),
                "prompt_security": _result(
                    "prompt_security",
                    _finding(
                        "prompt_security",
                        "No input validation detected",
                        Severity.MEDIUM,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Cross-Agent Prompt Injection" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_reviewer_tool_sharing_plus_tool_chain_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Reviewer agent shares privileged tool surface with executor",
                        Severity.HIGH,
                    ),
                ),
                "tool_chain": _result(
                    "tool_chain",
                    _finding(
                        "tool_chain",
                        "Network tool without allowlist",
                        Severity.HIGH,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Compromised Control Plane" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_shared_agent_identity_plus_exposed_credentials(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Multiple agents appear to share one identity or credential",
                        Severity.HIGH,
                    ),
                ),
                "dataflow": _result(
                    "dataflow",
                    _finding(
                        "dataflow",
                        "Hardcoded credential found in source",
                        Severity.HIGH,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Unattributable Agent Compromise" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_high_impact_action_plus_privileged_runtime(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "High-impact agent action lacks human escalation boundary",
                        Severity.HIGH,
                    ),
                ),
                "permission": _result(
                    "permission",
                    _finding(
                        "permission",
                        "Container runs in privileged mode",
                        Severity.HIGH,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Unchecked Production Change" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_shared_review_memory_plus_memory_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Reviewer and executor agents share mutable memory context",
                        Severity.HIGH,
                    ),
                ),
                "agent_memory": _result(
                    "agent_memory",
                    _finding(
                        "agent_memory",
                        "Memory poisoning vector detected",
                        Severity.MEDIUM,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Biased Agent Oversight" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.CRITICAL

    def test_suppressed_review_dissent_plus_cascade_risk(self):
        risks = correlate(
            {
                "agentic_review": _result(
                    "agentic_review",
                    _finding(
                        "agentic_review",
                        "Agent review dissent is suppressed without escalation",
                        Severity.MEDIUM,
                    ),
                ),
                "cascade": _result(
                    "cascade",
                    _finding(
                        "cascade",
                        "Cascade failure risk without fallback",
                        Severity.MEDIUM,
                    ),
                ),
            }
        )

        matching = [r for r in risks if "Silent Multi-Agent Failure" in r.name]
        assert len(matching) == 1
        assert matching[0].severity == Severity.HIGH
