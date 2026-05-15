"""Meta-agent analysis for systems where agents review or delegate to agents."""

from __future__ import annotations

import asyncio
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

AGENT_DEFINITION_PATTERNS = re.compile(
    r"(?:class\s+\w*(?:Agent|Reviewer|Critic)\b|"
    r"(?:Agent|Assistant|Crew|Task)\s*\(|"
    r"role\s*=\s*[\"'][^\"']*(?:agent|reviewer|critic|planner|executor)|"
    r"name\s*=\s*[\"'][^\"']*(?:agent|reviewer|critic|planner|executor))",
    re.IGNORECASE,
)

AGENT_REVIEW_PATTERNS = re.compile(
    r"(?:review_agent|critic_agent|judge_agent|reflection_agent|"
    r"self[_-]?review|self[_-]?critique|reviewer|critic|judge)",
    re.IGNORECASE,
)

INDEPENDENT_REVIEW_PATTERNS = re.compile(
    r"(?:independent|separate[_\s-]?model|different[_\s-]?model|"
    r"second[_\s-]?agent|external[_\s-]?review|human[_\s-]?review|"
    r"four[_\s-]?eyes|dual[_\s-]?control)",
    re.IGNORECASE,
)

DELEGATION_PATTERNS = re.compile(
    r"(?:delegate\s*\(|handoff\s*\(|transfer_to_agent|spawn_agent|"
    r"create_agent|run_agent|agent\.run|crew\.kickoff|"
    r"for\s+\w+\s+in\s+agents\s*:)",
    re.IGNORECASE,
)

RECURSION_GUARD_PATTERNS = re.compile(
    r"(?:max[_\s-]?(?:depth|hops|turns|steps|iterations|delegations)|"
    r"recursion[_\s-]?limit|visited_agents|seen_agents|cycle[_\s-]?detect|"
    r"delegation[_\s-]?budget)",
    re.IGNORECASE,
)

ROLE_PROMPT_PATTERNS = re.compile(
    r"(?:system_prompt|instructions|role_prompt|persona|goal|backstory)\s*[=:]",
    re.IGNORECASE,
)

POLICY_BOUNDARY_PATTERNS = re.compile(
    r"(?:policy|guardrail|constraint|allowed_tools|denied_tools|"
    r"approval|required_permissions|scope|sandbox|audit)",
    re.IGNORECASE,
)

REVIEW_DECISION_PATTERNS = re.compile(
    r"(?:approve|reject|score|verdict|grade|rank|risk_score|confidence|"
    r"quality_score|review_result)",
    re.IGNORECASE,
)

AUDIT_TRAIL_PATTERNS = re.compile(
    r"(?:audit|logger\.|logging\.|trace_id|correlation_id|decision_id|"
    r"review_id|evidence|rationale|reasoning|record_review|persist_review)",
    re.IGNORECASE,
)

QUORUM_REVIEW_PATTERNS = re.compile(
    r"(?:quorum|majority|consensus|vote|committee|panel|multi[_\s-]?review)",
    re.IGNORECASE,
)

SHARED_MODEL_PATTERNS = re.compile(
    r"(?:same[_\s-]?model|shared[_\s-]?model|model\s*=\s*[\"'][^\"']+[\"']|"
    r"provider\s*=\s*[\"'][^\"']+[\"']|llm\s*=\s*\w+)",
    re.IGNORECASE,
)

DIVERSITY_CONTROL_PATTERNS = re.compile(
    r"(?:diverse[_\s-]?models|different[_\s-]?providers|model[_\s-]?diversity|"
    r"provider[_\s-]?diversity|independent[_\s-]?providers|heterogeneous)",
    re.IGNORECASE,
)

AGENT_OUTPUT_TO_INSTRUCTION_PATTERNS = re.compile(
    r"(?:(?:system_prompt|instructions|prompt)\s*=.*(?:agent_output|agent_result|"
    r"previous_agent|delegate_result|response)|"
    r"messages\.append\s*\(.*(?:agent_output|agent_result|previous_agent|delegate_result)|"
    r"(?:handoff|delegate|run_agent)\s*\(.*(?:agent_output|agent_result|response))",
    re.IGNORECASE | re.DOTALL,
)

AGENT_OUTPUT_SANITIZATION_PATTERNS = re.compile(
    r"(?:sanitize[_\s-]?agent[_\s-]?output|validate[_\s-]?agent[_\s-]?output|"
    r"filter[_\s-]?agent[_\s-]?output|strip[_\s-]?instructions|"
    r"remove[_\s-]?tool[_\s-]?calls|trusted[_\s-]?handoff|handoff[_\s-]?schema)",
    re.IGNORECASE,
)

REVIEWER_SHARED_TOOLS_PATTERNS = re.compile(
    r"(?:reviewer[_\s-]?tools\s*=\s*(?:tools|agent_tools|executor_tools)|"
    r"critic[_\s-]?tools\s*=\s*(?:tools|agent_tools|executor_tools)|"
    r"(?:reviewer|critic|judge).*tools\s*=\s*tools|"
    r"tools\s*=\s*(?:agent|executor)\.tools)",
    re.IGNORECASE | re.DOTALL,
)

PRIVILEGED_TOOL_PATTERNS = re.compile(
    r"(?:delete|write|execute|deploy|admin|shell|filesystem|database|"
    r"payment|email|credential|secret|production)",
    re.IGNORECASE,
)

TOOL_SEPARATION_CONTROL_PATTERNS = re.compile(
    r"(?:reviewer[_\s-]?read[_\s-]?only|read[_\s-]?only[_\s-]?tools|"
    r"separate[_\s-]?reviewer[_\s-]?tools|deny[_\s-]?privileged|"
    r"reviewer[_\s-]?tool[_\s-]?allowlist|no[_\s-]?write[_\s-]?tools)",
    re.IGNORECASE,
)

SHARED_IDENTITY_PATTERNS = re.compile(
    r"(?:shared[_\s-]?(?:api[_\s-]?key|token|credential|service[_\s-]?account)|"
    r"(?:agent|reviewer|critic|executor).*api[_\s-]?key\s*=\s*(?:API_KEY|api_key|token)|"
    r"(?:agent|reviewer|critic|executor).*service[_\s-]?account\s*=\s*[\"'][^\"']+[\"']|"
    r"same[_\s-]?credential|global[_\s-]?agent[_\s-]?token)",
    re.IGNORECASE | re.DOTALL,
)

PER_AGENT_IDENTITY_PATTERNS = re.compile(
    r"(?:per[_\s-]?agent[_\s-]?(?:identity|token|credential|service[_\s-]?account)|"
    r"agent[_\s-]?id|actor[_\s-]?id|subject[_\s-]?claim|"
    r"delegated[_\s-]?credential|impersonation[_\s-]?scope|"
    r"least[_\s-]?privilege[_\s-]?identity)",
    re.IGNORECASE,
)

HIGH_IMPACT_ACTION_PATTERNS = re.compile(
    r"(?:deploy|delete|drop|write|payment|transfer|email|notify|approve|"
    r"reject|provision|revoke|production|customer[_\s-]?data|credential|secret)",
    re.IGNORECASE,
)

HUMAN_ESCALATION_PATTERNS = re.compile(
    r"(?:human[_\s-]?in[_\s-]?the[_\s-]?loop|human[_\s-]?approval|"
    r"manual[_\s-]?approval|approval[_\s-]?required|supervisor[_\s-]?approval|"
    r"override|kill[_\s-]?switch|break[_\s-]?glass|escalate[_\s-]?to[_\s-]?human|"
    r"two[_\s-]?person[_\s-]?review)",
    re.IGNORECASE,
)

SHARED_REVIEW_MEMORY_PATTERNS = re.compile(
    r"(?:shared[_\s-]?(?:memory|context|scratchpad|conversation|state)|"
    r"(?:reviewer|critic|judge).*memory\s*=\s*(?:memory|agent_memory|shared_memory)|"
    r"(?:executor|planner).*memory\s*=\s*(?:memory|agent_memory|shared_memory)|"
    r"same[_\s-]?(?:memory|context|conversation)|global[_\s-]?memory)",
    re.IGNORECASE | re.DOTALL,
)

MEMORY_ISOLATION_PATTERNS = re.compile(
    r"(?:separate[_\s-]?(?:memory|context|scratchpad)|isolated[_\s-]?memory|"
    r"reviewer[_\s-]?memory[_\s-]?namespace|memory[_\s-]?namespace|"
    r"read[_\s-]?only[_\s-]?memory|memory[_\s-]?integrity|"
    r"context[_\s-]?isolation)",
    re.IGNORECASE,
)

DISSENT_SIGNAL_PATTERNS = re.compile(
    r"(?:dissent|disagree|minority|low[_\s-]?confidence|confidence\s*<|"
    r"uncertain|conflict|tie|split[_\s-]?vote|review_failed)",
    re.IGNORECASE,
)

DISSENT_SUPPRESSION_PATTERNS = re.compile(
    r"(?:ignore[_\s-]?dissent|ignore[_\s-]?minority|auto[_\s-]?approve|"
    r"default[_\s-]?approve|approve[_\s-]?on[_\s-]?tie|"
    r"continue[_\s-]?on[_\s-]?disagreement|skip[_\s-]?review[_\s-]?failure|"
    r"fail[_\s-]?open)",
    re.IGNORECASE,
)

DISSENT_ESCALATION_PATTERNS = re.compile(
    r"(?:escalate[_\s-]?dissent|require[_\s-]?unanimous|manual[_\s-]?tie[_\s-]?break|"
    r"block[_\s-]?on[_\s-]?disagreement|fail[_\s-]?closed|"
    r"human[_\s-]?tie[_\s-]?break|review[_\s-]?appeal)",
    re.IGNORECASE,
)

SAME_AGENT_REVIEW_PATTERNS = re.compile(
    r"(?:reviewer\s*=\s*(?:agent|self)|critic\s*=\s*(?:agent|self)|"
    r"self\.review\s*\(|agent\.review\s*\(.*agent|"
    r"review_agent\s*=\s*agent)",
    re.IGNORECASE,
)

_SCAN_DIRS = "/app /src /opt /home"
_SOURCE_EXTENSIONS = "*.py *.js *.ts *.yaml *.yml *.json *.toml"


class AgenticReviewAgent(BaseAgent):
    """Analyze agent definitions, delegation, and agent-on-agent review."""

    name: ClassVar[str] = "agentic_review"
    description: ClassVar[str] = (
        "Detects unsafe agent-on-agent review and delegation patterns, including "
        "self-review, recursive delegation without budgets, and role prompts "
        "without explicit policy boundaries, review-decision audit trails, or "
        "model diversity controls for quorum review. Detects unsafe handoffs "
        "and reviewer agents sharing privileged executor tools, shared agent "
        "identity, high-impact actions without human escalation, shared review "
        "memory, and suppressed reviewer dissent."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["ASI02", "ASI03", "ASI08"]
    depends_on: ClassVar[list[str]] = ["tool_chain", "agent_memory"]

    async def analyze(self) -> None:
        """Run meta-agent security checks."""
        files = await self._collect_file_contents()
        if not files:
            self.add_finding(
                title="No source files for agentic review analysis",
                description="No source files were available to analyze agent-on-agent behavior.",
                severity=Severity.INFO,
                owasp_agentic=["ASI08"],
            )
            return

        combined = "\n".join(files.values())
        if not AGENT_DEFINITION_PATTERNS.search(combined):
            return

        self._check_self_review_without_independence(files)
        self._check_delegation_without_recursion_guard(files)
        self._check_role_prompts_without_policy_boundaries(files)
        self._check_review_decisions_without_audit_trail(files)
        self._check_quorum_review_without_model_diversity(files)
        self._check_agent_output_as_instruction_without_sanitization(files)
        self._check_reviewer_shared_privileged_tools(files)
        self._check_shared_agent_identity(files)
        self._check_high_impact_actions_without_human_escalation(files)
        self._check_shared_review_memory_without_isolation(files)
        self._check_dissent_suppression(files)

    def _exec(self, cmd: str) -> tuple[int, str]:
        if self.context.docker_manager is not None:
            return self.context.docker_manager.exec_in_target(cmd)
        return 1, ""

    async def _collect_file_contents(self) -> dict[str, str]:
        if not self.context.container_id and self.context.docker_manager is None:
            return {}

        ext_args = " -o ".join(f"-name '{ext}'" for ext in _SOURCE_EXTENSIONS.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            " -size -1024k 2>/dev/null | head -200"
        )
        try:
            rc, out = await asyncio.to_thread(self._exec, f"sh -c {find_cmd!r}")
            if rc != 0:
                return {}
        except Exception:
            return {}

        files: dict[str, str] = {}
        for fpath in out.strip().splitlines():
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                rc, content = await asyncio.to_thread(self._exec, f"head -c 65536 {fpath}")
            except Exception:
                continue
            if rc == 0 and content:
                files[fpath] = content
        return files

    def _check_self_review_without_independence(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            has_review = bool(
                AGENT_REVIEW_PATTERNS.search(content) or SAME_AGENT_REVIEW_PATTERNS.search(content)
            )
            if not has_review:
                continue
            if INDEPENDENT_REVIEW_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent review lacks independent reviewer boundary",
                description=(
                    "The code defines agent review or critique behavior but does not "
                    "show an independent reviewer, separate model, human review, or "
                    "dual-control boundary."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI03", "ASI08"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Agent review pattern without independence control",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Route high-impact agent decisions to an independent reviewer "
                    "agent, separate model, or human approval path with auditable "
                    "decision records."
                ),
            )

    def _check_delegation_without_recursion_guard(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            if not DELEGATION_PATTERNS.search(content):
                continue
            if RECURSION_GUARD_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent delegation lacks recursion or budget guard",
                description=(
                    "The code appears to delegate work between agents without a "
                    "declared maximum depth, turn budget, visited-agent tracking, "
                    "or cycle-detection control."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI02", "ASI08"],
                nist_ai_rmf=["MANAGE", "MEASURE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Delegation pattern without recursion guard",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Add max delegation depth, step budgets, cycle detection, and "
                    "explicit fallback behavior when the delegation budget is exhausted."
                ),
            )

    def _check_role_prompts_without_policy_boundaries(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            if not AGENT_DEFINITION_PATTERNS.search(content):
                continue
            if not ROLE_PROMPT_PATTERNS.search(content):
                continue
            if POLICY_BOUNDARY_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent role prompt lacks explicit policy boundary",
                description=(
                    "The code defines agent role prompts or personas without nearby "
                    "constraints for scope, tools, permissions, approvals, guardrails, "
                    "or audit logging."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI02", "ASI03"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Role prompt without policy boundary",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Attach explicit policy boundaries to every agent role: allowed "
                    "tools, denied actions, escalation rules, approval requirements, "
                    "and audit expectations."
                ),
            )

    def _check_review_decisions_without_audit_trail(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            has_review_decision = bool(
                AGENT_REVIEW_PATTERNS.search(content)
                and REVIEW_DECISION_PATTERNS.search(content)
            )
            if not has_review_decision:
                continue
            if AUDIT_TRAIL_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent review decision lacks audit trail",
                description=(
                    "The code appears to let an agent review, score, approve, or "
                    "reject another agent's output without recording evidence, "
                    "rationale, correlation IDs, or durable audit events."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI03", "ASI07"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Agent review decision without audit trail",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Persist review decisions with reviewer identity, reviewed "
                    "agent, input/output digests, score or verdict, rationale, "
                    "and correlation IDs for downstream governance review."
                ),
            )

    def _check_quorum_review_without_model_diversity(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            has_quorum = bool(
                QUORUM_REVIEW_PATTERNS.search(content)
                and AGENT_REVIEW_PATTERNS.search(content)
            )
            if not has_quorum:
                continue
            if not SHARED_MODEL_PATTERNS.search(content):
                continue
            if DIVERSITY_CONTROL_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Multi-agent review quorum lacks model diversity control",
                description=(
                    "The code appears to use quorum, voting, consensus, or panel "
                    "review between agents while sharing the same model, provider, "
                    "or LLM object. This can create correlated reviewer failures "
                    "that look independent but share the same blind spots."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI03", "ASI08"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Quorum review without model/provider diversity control",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Use reviewer diversity controls for high-impact decisions: "
                    "different models or providers, independent prompts, separate "
                    "tool permissions, and explicit disagreement handling."
                ),
            )

    def _check_agent_output_as_instruction_without_sanitization(
        self, files: dict[str, str]
    ) -> None:
        for fpath, content in files.items():
            if not AGENT_OUTPUT_TO_INSTRUCTION_PATTERNS.search(content):
                continue
            if AGENT_OUTPUT_SANITIZATION_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent output is reused as downstream instructions without sanitization",
                description=(
                    "The code appears to pass one agent's output into another "
                    "agent's prompt, instructions, messages, or handoff call "
                    "without a sanitization or structured handoff boundary. "
                    "A compromised upstream agent can inject instructions into "
                    "the downstream agent."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI01", "ASI03"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Agent output reused as downstream instructions",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Use typed handoff schemas and sanitize agent outputs before "
                    "placing them in downstream instructions. Strip tool calls, "
                    "role directives, and instruction-like content from handoffs."
                ),
            )

    def _check_reviewer_shared_privileged_tools(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            has_shared_tools = REVIEWER_SHARED_TOOLS_PATTERNS.search(content)
            if not has_shared_tools:
                continue
            if not PRIVILEGED_TOOL_PATTERNS.search(content):
                continue
            if TOOL_SEPARATION_CONTROL_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Reviewer agent shares privileged tool surface with executor",
                description=(
                    "The code appears to give reviewer, critic, or judge agents "
                    "the same privileged tools as the executor agent. A reviewer "
                    "that can mutate state, execute commands, or access secrets "
                    "is not an independent control boundary."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI02", "ASI03"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Reviewer shares privileged executor tools",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Use a separate reviewer tool allowlist. Prefer read-only "
                    "inspection tools for reviewer agents and deny write, execute, "
                    "deployment, credential, and production-impacting tools."
                ),
            )

    def _check_shared_agent_identity(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            if not SHARED_IDENTITY_PATTERNS.search(content):
                continue
            if PER_AGENT_IDENTITY_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Multiple agents appear to share one identity or credential",
                description=(
                    "The code appears to reuse one API key, token, credential, "
                    "or service account across agent roles. Shared identity makes "
                    "agent actions hard to attribute and weakens least-privilege "
                    "boundaries between planner, executor, reviewer, and critic agents."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI02", "ASI07"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Shared agent identity or credential pattern",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Issue per-agent identities or delegated credentials with "
                    "least-privilege scopes. Include agent_id or actor claims in "
                    "tool calls, logs, approvals, and downstream audit events."
                ),
            )

    def _check_high_impact_actions_without_human_escalation(
        self, files: dict[str, str]
    ) -> None:
        for fpath, content in files.items():
            has_agent = AGENT_DEFINITION_PATTERNS.search(content)
            has_delegation = DELEGATION_PATTERNS.search(content) or AGENT_REVIEW_PATTERNS.search(content)
            if not (has_agent and has_delegation):
                continue
            if not HIGH_IMPACT_ACTION_PATTERNS.search(content):
                continue
            if HUMAN_ESCALATION_PATTERNS.search(content):
                continue
            self.add_finding(
                title="High-impact agent action lacks human escalation boundary",
                description=(
                    "The code appears to allow agent delegation or review flows "
                    "to approve, deploy, delete, revoke, write, notify, or access "
                    "sensitive data without an explicit human approval, override, "
                    "kill switch, or break-glass boundary."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI02", "ASI03"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="High-impact agent action without human escalation",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Require human approval or supervisor override for high-impact "
                    "agent actions. Add kill-switch and break-glass controls with "
                    "auditable approval records."
                ),
            )

    def _check_shared_review_memory_without_isolation(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            if not SHARED_REVIEW_MEMORY_PATTERNS.search(content):
                continue
            if MEMORY_ISOLATION_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Reviewer and executor agents share mutable memory context",
                description=(
                    "The code appears to share memory, scratchpad, conversation, "
                    "or global context between executor and reviewer agents without "
                    "an isolation, namespace, read-only, or integrity boundary. "
                    "A poisoned executor context can bias or control the reviewer."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI03", "ASI06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Shared mutable review memory without isolation",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Use separate reviewer memory namespaces, read-only evidence "
                    "snapshots, and memory integrity checks. Do not let the executor "
                    "write to reviewer context or critique state."
                ),
            )

    def _check_dissent_suppression(self, files: dict[str, str]) -> None:
        for fpath, content in files.items():
            has_review = AGENT_REVIEW_PATTERNS.search(content) or QUORUM_REVIEW_PATTERNS.search(content)
            if not has_review:
                continue
            if not (
                DISSENT_SIGNAL_PATTERNS.search(content)
                and DISSENT_SUPPRESSION_PATTERNS.search(content)
            ):
                continue
            if DISSENT_ESCALATION_PATTERNS.search(content):
                continue
            self.add_finding(
                title="Agent review dissent is suppressed without escalation",
                description=(
                    "The code appears to ignore dissent, minority votes, low "
                    "confidence, ties, or review failures and continue or approve "
                    "by default. This weakens multi-agent review because disagreement "
                    "does not trigger investigation or human escalation."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI03", "ASI08"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[
                    Evidence(
                        type="source_pattern",
                        summary="Review dissent suppressed without escalation",
                        location=fpath,
                    )
                ],
                remediation=(
                    "Fail closed on review disagreement for high-impact actions. "
                    "Escalate dissent, ties, review failures, or low confidence to "
                    "a human or independent reviewer with recorded rationale."
                ),
            )
