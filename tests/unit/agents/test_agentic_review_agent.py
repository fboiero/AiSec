"""Tests for AgenticReviewAgent."""

from __future__ import annotations

import pytest

from aisec.agents.agentic_review import (
    AGENT_DEFINITION_PATTERNS,
    AGENT_OUTPUT_SANITIZATION_PATTERNS,
    AGENT_OUTPUT_TO_INSTRUCTION_PATTERNS,
    AGENT_REVIEW_PATTERNS,
    AUDIT_TRAIL_PATTERNS,
    DELEGATION_PATTERNS,
    DIVERSITY_CONTROL_PATTERNS,
    DISSENT_ESCALATION_PATTERNS,
    DISSENT_SIGNAL_PATTERNS,
    DISSENT_SUPPRESSION_PATTERNS,
    HIGH_IMPACT_ACTION_PATTERNS,
    HUMAN_ESCALATION_PATTERNS,
    INDEPENDENT_REVIEW_PATTERNS,
    MEMORY_ISOLATION_PATTERNS,
    PER_AGENT_IDENTITY_PATTERNS,
    POLICY_BOUNDARY_PATTERNS,
    QUORUM_REVIEW_PATTERNS,
    PRIVILEGED_TOOL_PATTERNS,
    RECURSION_GUARD_PATTERNS,
    REVIEWER_SHARED_TOOLS_PATTERNS,
    REVIEW_DECISION_PATTERNS,
    ROLE_PROMPT_PATTERNS,
    SHARED_IDENTITY_PATTERNS,
    SHARED_MODEL_PATTERNS,
    SHARED_REVIEW_MEMORY_PATTERNS,
    TOOL_SEPARATION_CONTROL_PATTERNS,
    AgenticReviewAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestAgenticReviewMetadata:
    def test_name(self):
        assert AgenticReviewAgent.name == "agentic_review"

    def test_phase(self):
        assert AgenticReviewAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "ASI02" in AgenticReviewAgent.frameworks
        assert "ASI08" in AgenticReviewAgent.frameworks

    def test_dependencies(self):
        assert AgenticReviewAgent.depends_on == ["tool_chain", "agent_memory"]


class TestAgenticReviewPatterns:
    def test_agent_definition_patterns_match(self):
        assert AGENT_DEFINITION_PATTERNS.search("class PlannerAgent:")
        assert AGENT_DEFINITION_PATTERNS.search("role='critic agent'")

    def test_review_patterns_match(self):
        assert AGENT_REVIEW_PATTERNS.search("self_review(result)")
        assert AGENT_REVIEW_PATTERNS.search("critic_agent = Agent()")

    def test_independent_review_patterns_match(self):
        assert INDEPENDENT_REVIEW_PATTERNS.search("human_review=True")
        assert INDEPENDENT_REVIEW_PATTERNS.search("separate_model='gpt-reviewer'")

    def test_delegation_patterns_match(self):
        assert DELEGATION_PATTERNS.search("delegate(task)")
        assert DELEGATION_PATTERNS.search("spawn_agent('reviewer')")

    def test_recursion_guard_patterns_match(self):
        assert RECURSION_GUARD_PATTERNS.search("max_delegations=3")
        assert RECURSION_GUARD_PATTERNS.search("visited_agents.add(name)")

    def test_role_policy_patterns_match(self):
        assert ROLE_PROMPT_PATTERNS.search("system_prompt = 'You are a planner'")
        assert POLICY_BOUNDARY_PATTERNS.search("allowed_tools=['search']")

    def test_review_decision_and_audit_patterns_match(self):
        assert REVIEW_DECISION_PATTERNS.search("verdict = approve(result)")
        assert AUDIT_TRAIL_PATTERNS.search("record_review(review_id, rationale)")

    def test_quorum_and_diversity_patterns_match(self):
        assert QUORUM_REVIEW_PATTERNS.search("consensus = vote(reviewers)")
        assert SHARED_MODEL_PATTERNS.search("model='gpt-reviewer'")
        assert DIVERSITY_CONTROL_PATTERNS.search("different_providers=True")

    def test_agent_output_instruction_patterns_match(self):
        assert AGENT_OUTPUT_TO_INSTRUCTION_PATTERNS.search(
            "instructions = previous_agent.response"
        )
        assert AGENT_OUTPUT_SANITIZATION_PATTERNS.search("handoff_schema = AgentHandoff")

    def test_reviewer_shared_tool_patterns_match(self):
        assert REVIEWER_SHARED_TOOLS_PATTERNS.search("reviewer_tools = executor_tools")
        assert PRIVILEGED_TOOL_PATTERNS.search("delete production database")
        assert TOOL_SEPARATION_CONTROL_PATTERNS.search("reviewer_read_only=True")

    def test_identity_and_escalation_patterns_match(self):
        assert SHARED_IDENTITY_PATTERNS.search("shared_api_key = API_KEY")
        assert PER_AGENT_IDENTITY_PATTERNS.search("per_agent_identity=True")
        assert HIGH_IMPACT_ACTION_PATTERNS.search("deploy to production")
        assert HUMAN_ESCALATION_PATTERNS.search("human_approval_required=True")

    def test_memory_and_dissent_patterns_match(self):
        assert SHARED_REVIEW_MEMORY_PATTERNS.search("reviewer.memory = shared_memory")
        assert MEMORY_ISOLATION_PATTERNS.search("reviewer_memory_namespace='review'")
        assert DISSENT_SIGNAL_PATTERNS.search("low_confidence = True")
        assert DISSENT_SUPPRESSION_PATTERNS.search("approve_on_tie = True")
        assert DISSENT_ESCALATION_PATTERNS.search("block_on_disagreement=True")


class TestAgenticReviewNoContainer:
    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        await agent.analyze()

        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestAgenticReviewFindings:
    def test_detects_self_review_without_independence(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/agents.py": (
                "review_agent = agent\n"
                "def self_review(result):\n"
                "    return agent.review(result)\n"
            )
        }

        agent._check_self_review_without_independence(files)

        findings = [f for f in agent.findings if "independent reviewer" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_independent_review_boundary_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/agents.py": (
                "critic_agent = Agent(role='reviewer')\n"
                "separate_model = 'gpt-reviewer'\n"
                "human_review = True\n"
            )
        }

        agent._check_self_review_without_independence(files)

        assert not agent.findings

    def test_detects_delegation_without_recursion_guard(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/orchestrator.py": (
                "class PlannerAgent:\n"
                "    def run(self, task):\n"
                "        return delegate(task)\n"
            )
        }

        agent._check_delegation_without_recursion_guard(files)

        findings = [f for f in agent.findings if "recursion" in f.title.lower()]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_delegation_with_budget_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/orchestrator.py": (
                "class PlannerAgent:\n"
                "    max_delegations = 3\n"
                "    def run(self, task):\n"
                "        return delegate(task)\n"
            )
        }

        agent._check_delegation_without_recursion_guard(files)

        assert not agent.findings

    def test_detects_role_prompt_without_policy_boundary(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/agents.py": (
                "researcher = Agent(\n"
                "    role='research agent',\n"
                "    system_prompt='Find the answer using every method available.'\n"
                ")\n"
            )
        }

        agent._check_role_prompts_without_policy_boundaries(files)

        findings = [f for f in agent.findings if "policy boundary" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_role_prompt_with_policy_boundary_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/agents.py": (
                "researcher = Agent(\n"
                "    role='research agent',\n"
                "    system_prompt='Research only within scope.',\n"
                "    allowed_tools=['search'],\n"
                "    approval_required=True,\n"
                ")\n"
            )
        }

        agent._check_role_prompts_without_policy_boundaries(files)

        assert not agent.findings

    def test_detects_review_decision_without_audit_trail(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/review.py": (
                "critic_agent = Agent(role='reviewer')\n"
                "def review_agent_output(output):\n"
                "    verdict = approve(output)\n"
                "    return verdict\n"
            )
        }

        agent._check_review_decisions_without_audit_trail(files)

        findings = [f for f in agent.findings if "audit trail" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_review_decision_with_audit_trail_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/review.py": (
                "critic_agent = Agent(role='reviewer')\n"
                "def review_agent_output(output):\n"
                "    verdict = approve(output)\n"
                "    record_review(review_id, verdict, rationale='policy matched')\n"
                "    return verdict\n"
            )
        }

        agent._check_review_decisions_without_audit_trail(files)

        assert not agent.findings

    def test_detects_quorum_review_without_model_diversity(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/quorum.py": (
                "reviewers = [critic_agent, judge_agent]\n"
                "model='gpt-reviewer'\n"
                "def review_agent_output(output):\n"
                "    consensus = vote(reviewers, output)\n"
                "    return consensus\n"
            )
        }

        agent._check_quorum_review_without_model_diversity(files)

        findings = [f for f in agent.findings if "model diversity" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_quorum_review_with_model_diversity_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/quorum.py": (
                "reviewers = [critic_agent, judge_agent]\n"
                "model='gpt-reviewer'\n"
                "different_providers = True\n"
                "def review_agent_output(output):\n"
                "    consensus = vote(reviewers, output)\n"
                "    return consensus\n"
            )
        }

        agent._check_quorum_review_without_model_diversity(files)

        assert not agent.findings

    def test_detects_agent_output_as_instruction_without_sanitization(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/handoff.py": (
                "planner_agent = Agent(role='planner agent')\n"
                "executor_agent = Agent(role='executor agent')\n"
                "agent_output = planner_agent.run(task)\n"
                "instructions = agent_output\n"
                "executor_agent.run(instructions)\n"
            )
        }

        agent._check_agent_output_as_instruction_without_sanitization(files)

        findings = [f for f in agent.findings if "downstream instructions" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_agent_output_with_sanitized_handoff_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/handoff.py": (
                "planner_agent = Agent(role='planner agent')\n"
                "agent_output = planner_agent.run(task)\n"
                "handoff_schema = AgentHandoff\n"
                "safe_output = sanitize_agent_output(agent_output)\n"
                "executor_agent.run(safe_output)\n"
            )
        }

        agent._check_agent_output_as_instruction_without_sanitization(files)

        assert not agent.findings

    def test_detects_reviewer_sharing_privileged_tools(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/reviewer.py": (
                "executor_tools = [delete_file, execute_shell, read_secret]\n"
                "critic_agent = Agent(role='critic agent')\n"
                "reviewer_tools = executor_tools\n"
            )
        }

        agent._check_reviewer_shared_privileged_tools(files)

        findings = [f for f in agent.findings if "privileged tool surface" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_reviewer_with_separate_read_only_tools_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/reviewer.py": (
                "executor_tools = [delete_file, execute_shell, read_secret]\n"
                "reviewer_tools = executor_tools\n"
                "reviewer_read_only = True\n"
                "reviewer_tool_allowlist = ['inspect_plan']\n"
            )
        }

        agent._check_reviewer_shared_privileged_tools(files)

        assert not agent.findings

    def test_detects_shared_agent_identity(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/identity.py": (
                "planner_agent = Agent(role='planner agent', api_key=API_KEY)\n"
                "executor_agent = Agent(role='executor agent', api_key=API_KEY)\n"
                "reviewer_agent = Agent(role='reviewer agent', api_key=API_KEY)\n"
                "shared_api_key = API_KEY\n"
            )
        }

        agent._check_shared_agent_identity(files)

        findings = [f for f in agent.findings if "share one identity" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_per_agent_identity_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/identity.py": (
                "shared_service_account = 'agent-platform'\n"
                "per_agent_identity = True\n"
                "agent_id = claims['sub']\n"
                "least_privilege_identity = scopes.for_agent(agent_id)\n"
            )
        }

        agent._check_shared_agent_identity(files)

        assert not agent.findings

    def test_detects_high_impact_action_without_human_escalation(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/actions.py": (
                "executor_agent = Agent(role='executor agent')\n"
                "def run(task):\n"
                "    verdict = review_agent(task)\n"
                "    if verdict == 'approve':\n"
                "        deploy_to_production(task)\n"
                "        delete_customer_data(task)\n"
            )
        }

        agent._check_high_impact_actions_without_human_escalation(files)

        findings = [f for f in agent.findings if "human escalation" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_high_impact_action_with_human_approval_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/actions.py": (
                "executor_agent = Agent(role='executor agent')\n"
                "def run(task):\n"
                "    verdict = review_agent(task)\n"
                "    human_approval_required = True\n"
                "    if supervisor_approval(task):\n"
                "        deploy_to_production(task)\n"
            )
        }

        agent._check_high_impact_actions_without_human_escalation(files)

        assert not agent.findings

    def test_detects_shared_review_memory_without_isolation(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/memory.py": (
                "shared_memory = ConversationBufferMemory()\n"
                "executor_agent = Agent(role='executor agent', memory=shared_memory)\n"
                "reviewer_agent = Agent(role='reviewer agent', memory=shared_memory)\n"
            )
        }

        agent._check_shared_review_memory_without_isolation(files)

        findings = [f for f in agent.findings if "share mutable memory" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_shared_review_memory_with_isolation_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/memory.py": (
                "shared_memory = ConversationBufferMemory()\n"
                "reviewer_memory_namespace = 'reviewer-evidence'\n"
                "read_only_memory = True\n"
                "reviewer_agent = Agent(role='reviewer agent', memory=shared_memory)\n"
            )
        }

        agent._check_shared_review_memory_without_isolation(files)

        assert not agent.findings

    def test_detects_dissent_suppression_without_escalation(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/review_policy.py": (
                "critic_agent = Agent(role='critic agent')\n"
                "def review_agent_output(output):\n"
                "    if low_confidence or dissent:\n"
                "        return auto_approve(output)\n"
                "    return approve(output)\n"
            )
        }

        agent._check_dissent_suppression(files)

        findings = [f for f in agent.findings if "dissent is suppressed" in f.title]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_dissent_escalation_passes(self, scan_context):
        agent = AgenticReviewAgent(scan_context)
        files = {
            "/app/review_policy.py": (
                "critic_agent = Agent(role='critic agent')\n"
                "def review_agent_output(output):\n"
                "    if low_confidence or dissent:\n"
                "        block_on_disagreement = True\n"
                "        return escalate_dissent(output)\n"
                "    return approve(output)\n"
            )
        }

        agent._check_dissent_suppression(files)

        assert not agent.findings
