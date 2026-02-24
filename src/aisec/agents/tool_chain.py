"""Tool chain and function calling security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Tool decorator patterns (LangChain, CrewAI, OpenAI, custom)
TOOL_DECORATOR_PATTERN = re.compile(
    r'@(?:tool|langchain_tool|crewai\.tool|function_tool|'
    r'register_tool|BaseTool|server\.tool|mcp\.tool)\b',
    re.IGNORECASE,
)

# Tool class patterns
TOOL_CLASS_PATTERN = re.compile(
    r'class\s+\w+(?:Tool|Action)\s*\(.*(?:BaseTool|Tool|Action|StructuredTool)',
)

# Code execution in tools
EXEC_PATTERNS = re.compile(
    r'(?:exec\s*\(|eval\s*\(|compile\s*\(.*exec)',
)

SUBPROCESS_PATTERNS = re.compile(
    r'(?:subprocess\.\w+\s*\(|os\.system\s*\(|os\.popen\s*\(|Popen\s*\()',
)

# Sandbox/isolation patterns
SANDBOX_PATTERNS = re.compile(
    r'(?:docker|sandbox|container|isolat|jail|chroot|'
    r'seccomp|AppArmor|nsjail|firejail|bubblewrap)',
    re.IGNORECASE,
)

# File system operations in tools
FILE_OPS_PATTERNS = re.compile(
    r'(?:open\s*\(|pathlib\.Path|os\.path\.\w+|'
    r'shutil\.\w+|os\.makedirs|os\.remove|os\.unlink|'
    r'os\.rename|os\.listdir|glob\.glob)',
)

# Path validation / restriction
PATH_RESTRICT_PATTERNS = re.compile(
    r'(?:allowed_paths|path_allowlist|base_dir|chroot|'
    r'is_relative_to|startswith.*(?:base|root|allowed)|'
    r'resolve\(\)|sanitize.*path|validate.*path)',
    re.IGNORECASE,
)

# Network operations in tools
NETWORK_OPS_PATTERNS = re.compile(
    r'(?:requests\.(?:get|post|put|delete|patch)|'
    r'httpx\.(?:get|post|put|delete|patch|AsyncClient|Client)|'
    r'urllib\.request|aiohttp\.ClientSession|'
    r'socket\.connect|urlopen)',
)

# URL validation / allowlist
URL_RESTRICT_PATTERNS = re.compile(
    r'(?:allowed_domains|url_allowlist|domain_allowlist|'
    r'validate_url|allowed_urls|url_whitelist|'
    r'check_url|safe_url)',
    re.IGNORECASE,
)

# SQL injection in tools
SQL_FORMAT_PATTERNS = re.compile(
    r'(?:execute|executemany)\s*\(\s*(?:f["\']|["\'].*%[sd]|["\'].*\.format)',
)

SQL_SAFE_PATTERNS = re.compile(
    r'(?:execute\s*\(\s*["\'].*%s|execute\s*\(\s*["\'].*\?|'
    r'parameterize|prepared_statement|sqlalchemy|ORM)',
    re.IGNORECASE,
)

# Tool output → prompt injection
TOOL_OUTPUT_TO_PROMPT = re.compile(
    r'(?:(?:system|user|assistant)\s*.*(?:tool_result|tool_output|result)|'
    r'f["\'].*(?:tool|result|output).*["\'].*(?:role|message|content)|'
    r'messages\.append.*(?:tool|result)|'
    r'prompt.*(?:tool_result|tool_output))',
    re.IGNORECASE,
)

OUTPUT_SANITIZE_PATTERNS = re.compile(
    r'(?:sanitize.*output|clean.*result|escape.*result|'
    r'filter.*tool.*output|validate.*response)',
    re.IGNORECASE,
)

# Agent executor / chain patterns
AGENT_EXECUTOR_PATTERNS = re.compile(
    r'(?:AgentExecutor|create_react_agent|create_tool_calling_agent|'
    r'initialize_agent|run_agent|agent_chain)',
)

# Max iterations / loop protection
MAX_ITER_PATTERNS = re.compile(
    r'(?:max_iterations|max_steps|max_turns|max_loops|'
    r'iteration_limit|step_limit|max_execution_steps|'
    r'early_stopping|max_retries)',
    re.IGNORECASE,
)

# Error handling patterns
ERROR_HANDLING_PATTERNS = re.compile(
    r'(?:try\s*:|except\s+\w|handle_tool_error|'
    r'error_handler|on_tool_error)',
)

# Auth / permission patterns on tools
TOOL_AUTH_PATTERNS = re.compile(
    r'(?:require_auth|permission_required|login_required|'
    r'role_required|check_permission|authorize|'
    r'@admin|@authenticated|@requires_role)',
    re.IGNORECASE,
)

# Privileged tool indicators
PRIVILEGED_TOOL_PATTERNS = re.compile(
    r'(?:delete|remove|drop|destroy|admin|modify|update|write|create|'
    r'execute|deploy|install|configure|reset|revoke)',
    re.IGNORECASE,
)

# Tool logging / audit
TOOL_LOGGING_PATTERNS = re.compile(
    r'(?:logger\.|logging\.|audit|log_tool|tool_log|'
    r'track.*tool|record.*call|telemetry)',
    re.IGNORECASE,
)

# Dangerous tool descriptions
DANGEROUS_DESC_PATTERNS = re.compile(
    r'(?:ignore previous|override|bypass|skip validation|'
    r'no restrictions|unlimited access|full control|'
    r'admin mode|god mode)',
    re.IGNORECASE,
)


class ToolChainSecurityAgent(BaseAgent):
    """Detects dangerous function calling and tool use patterns."""

    name: ClassVar[str] = "tool_chain"
    description: ClassVar[str] = (
        "Detects dangerous function calling and tool use patterns: code "
        "execution without sandbox, file/network/DB tools without restrictions, "
        "tool output injection, and unrestricted chaining."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM06", "ASI02", "ASI05"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze tool chain security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for tool chain analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_agentic=["ASI02"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        # Only run if tool patterns detected
        has_tools = bool(
            TOOL_DECORATOR_PATTERN.search(combined)
            or TOOL_CLASS_PATTERN.search(combined)
        )
        if not has_tools:
            return

        self._check_code_exec_no_sandbox(all_content)
        self._check_file_no_restrictions(all_content)
        self._check_network_no_allowlist(all_content)
        self._check_sql_injection(all_content)
        self._check_output_injection(all_content, combined)
        self._check_unrestricted_chaining(combined)
        self._check_error_handling(all_content)
        self._check_privileged_no_auth(all_content)
        self._check_tool_descriptions(all_content)
        self._check_tool_logging(combined)

    def _check_code_exec_no_sandbox(self, files: dict[str, str]) -> None:
        """Check for code execution tools without sandboxing."""
        for fpath, content in files.items():
            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if not has_tool:
                continue

            exec_matches = list(EXEC_PATTERNS.finditer(content))
            sub_matches = list(SUBPROCESS_PATTERNS.finditer(content))
            all_matches = exec_matches + sub_matches

            if not all_matches:
                continue

            has_sandbox = bool(SANDBOX_PATTERNS.search(content))
            if not has_sandbox:
                lines = [str(content[:m.start()].count("\n") + 1) for m in all_matches]
                self.add_finding(
                    title="Code execution tool without sandbox",
                    description=(
                        f"Tool at {fpath} (lines: {', '.join(lines)}) uses exec/eval/"
                        "subprocess without sandboxing. An LLM could be manipulated "
                        "into executing arbitrary code."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_agentic=["ASI05", "ASI02"],
                    owasp_llm=["LLM06"],
                    nist_ai_rmf=["GOVERN", "MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unsandboxed code execution at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Run code execution in an isolated sandbox (Docker container, "
                        "nsjail, or gVisor) with resource limits and network isolation."
                    ),
                    cvss_score=9.5,
                    ai_risk_score=9.5,
                )

    def _check_file_no_restrictions(self, files: dict[str, str]) -> None:
        """Check for file tools without path restrictions."""
        for fpath, content in files.items():
            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if not has_tool:
                continue

            has_file_ops = bool(FILE_OPS_PATTERNS.search(content))
            has_restriction = bool(PATH_RESTRICT_PATTERNS.search(content))

            if has_file_ops and not has_restriction:
                self.add_finding(
                    title="File system tool without path restrictions",
                    description=(
                        f"Tool at {fpath} performs file operations without path "
                        "validation or directory restrictions. An LLM could access "
                        "or modify files outside the intended scope."
                    ),
                    severity=Severity.HIGH,
                    owasp_agentic=["ASI02"],
                    owasp_llm=["LLM06"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unrestricted file access at {fpath}",
                        location=fpath,
                    )],
                    remediation=(
                        "Implement path allowlists: resolve paths and verify they "
                        "start with the base directory using Path.is_relative_to()."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_network_no_allowlist(self, files: dict[str, str]) -> None:
        """Check for network tools without URL allowlists."""
        for fpath, content in files.items():
            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if not has_tool:
                continue

            has_network = bool(NETWORK_OPS_PATTERNS.search(content))
            has_restrict = bool(URL_RESTRICT_PATTERNS.search(content))

            if has_network and not has_restrict:
                self.add_finding(
                    title="Network tool without URL allowlist",
                    description=(
                        f"Tool at {fpath} makes HTTP requests without URL validation "
                        "or domain allowlisting. An LLM could be tricked into making "
                        "requests to internal services (SSRF) or malicious endpoints."
                    ),
                    severity=Severity.HIGH,
                    owasp_agentic=["ASI02"],
                    owasp_llm=["LLM06"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unrestricted network tool at {fpath}",
                        location=fpath,
                    )],
                    remediation=(
                        "Implement a URL allowlist for network tools. Validate "
                        "URLs against allowed domains before making requests."
                    ),
                    cvss_score=7.5,
                    ai_risk_score=7.0,
                )

    def _check_sql_injection(self, files: dict[str, str]) -> None:
        """Check for SQL injection in tool functions."""
        for fpath, content in files.items():
            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if not has_tool:
                continue

            sql_matches = list(SQL_FORMAT_PATTERNS.finditer(content))
            if sql_matches:
                lines = [str(content[:m.start()].count("\n") + 1) for m in sql_matches]
                self.add_finding(
                    title="SQL injection in tool function",
                    description=(
                        f"Tool at {fpath} (lines: {', '.join(lines)}) constructs "
                        "SQL queries using string formatting. An LLM could inject "
                        "SQL payloads through tool parameters."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_agentic=["ASI02", "ASI05"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"SQL injection risk at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use parameterized queries: cursor.execute('SELECT * WHERE id = %s', (id,)). "
                        "Never use f-strings or .format() in SQL queries."
                    ),
                    cvss_score=9.0,
                    ai_risk_score=8.5,
                )

    def _check_output_injection(self, files: dict[str, str], combined: str) -> None:
        """Check for tool output injected into prompts."""
        has_output_to_prompt = bool(TOOL_OUTPUT_TO_PROMPT.search(combined))
        has_sanitization = bool(OUTPUT_SANITIZE_PATTERNS.search(combined))

        if has_output_to_prompt and not has_sanitization:
            self.add_finding(
                title="Tool output injection: results used as instructions",
                description=(
                    "Tool return values are concatenated into LLM prompts without "
                    "sanitization. A malicious tool response could inject instructions "
                    "that hijack the agent's behavior."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI01"],
                owasp_llm=["LLM01"],
                remediation=(
                    "Sanitize tool outputs before inserting into prompts. "
                    "Use structured output formats and validate tool responses."
                ),
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    def _check_unrestricted_chaining(self, combined: str) -> None:
        """Check for unrestricted tool chain execution."""
        has_executor = bool(AGENT_EXECUTOR_PATTERNS.search(combined))
        has_max_iter = bool(MAX_ITER_PATTERNS.search(combined))

        if has_executor and not has_max_iter:
            self.add_finding(
                title="Unrestricted tool chaining without iteration limit",
                description=(
                    "Agent executor detected without max_iterations or step limits. "
                    "The agent could enter infinite tool-calling loops, causing "
                    "resource exhaustion and cost overruns."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                remediation=(
                    "Set max_iterations on agent executors: "
                    "AgentExecutor(max_iterations=10, early_stopping_method='force')"
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_error_handling(self, files: dict[str, str]) -> None:
        """Check for tools without error handling."""
        for fpath, content in files.items():
            tool_matches = list(TOOL_DECORATOR_PATTERN.finditer(content))
            if not tool_matches:
                continue

            has_error_handling = bool(ERROR_HANDLING_PATTERNS.search(content))
            if not has_error_handling:
                self.add_finding(
                    title="Tool functions without error handling",
                    description=(
                        f"Tool(s) at {fpath} lack try/except error handling. "
                        "Unhandled exceptions could leak stack traces and internal "
                        "paths to the LLM, enabling reconnaissance."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM07"],
                    owasp_agentic=["ASI02"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"No error handling at {fpath}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add try/except blocks in tool functions. Return safe error "
                        "messages instead of exposing stack traces."
                    ),
                    cvss_score=4.0,
                    ai_risk_score=4.0,
                )

    def _check_privileged_no_auth(self, files: dict[str, str]) -> None:
        """Check for privileged tools without auth decorators."""
        for fpath, content in files.items():
            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if not has_tool:
                continue

            has_privileged = bool(PRIVILEGED_TOOL_PATTERNS.search(content))
            has_auth = bool(TOOL_AUTH_PATTERNS.search(content))

            if has_privileged and not has_auth:
                self.add_finding(
                    title="Privileged tool without authentication",
                    description=(
                        f"Tool at {fpath} performs privileged operations "
                        "(delete, modify, admin) without authentication or "
                        "role-based access control."
                    ),
                    severity=Severity.HIGH,
                    owasp_agentic=["ASI02", "ASI03"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unauthenticated privileged tool at {fpath}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add authentication and role checks to privileged tools. "
                        "Use @require_auth or @role_required decorators."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_tool_descriptions(self, files: dict[str, str]) -> None:
        """Check for tool descriptions with dangerous instructions."""
        for fpath, content in files.items():
            desc_matches = list(DANGEROUS_DESC_PATTERNS.finditer(content))
            if not desc_matches:
                continue

            has_tool = bool(TOOL_DECORATOR_PATTERN.search(content) or TOOL_CLASS_PATTERN.search(content))
            if has_tool:
                lines = [str(content[:m.start()].count("\n") + 1) for m in desc_matches]
                self.add_finding(
                    title="Tool description contains dangerous instructions",
                    description=(
                        f"Tool at {fpath} (lines: {', '.join(lines)}) has a description "
                        "containing override/bypass language that could mislead the LLM "
                        "into unsafe behavior."
                    ),
                    severity=Severity.LOW,
                    owasp_agentic=["ASI01"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Dangerous tool description at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Review tool descriptions for language that could be "
                        "interpreted as instructions to bypass safety measures."
                    ),
                    cvss_score=3.0,
                    ai_risk_score=4.0,
                )

    def _check_tool_logging(self, combined: str) -> None:
        """Check for absence of tool call logging."""
        has_tools = bool(
            TOOL_DECORATOR_PATTERN.search(combined)
            or TOOL_CLASS_PATTERN.search(combined)
        )
        has_logging = bool(TOOL_LOGGING_PATTERNS.search(combined))

        if has_tools and not has_logging:
            self.add_finding(
                title="No tool call logging or audit trail",
                description=(
                    "Tool invocations are not logged or audited. Without an audit "
                    "trail, malicious tool usage cannot be detected or investigated."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI02"],
                remediation=(
                    "Add logging to all tool invocations. Record tool name, parameters, "
                    "caller identity, timestamp, and result status."
                ),
                cvss_score=4.0,
                ai_risk_score=5.0,
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect Python source files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f -name '*.py' "
            "-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _read_file(self, fpath: str) -> str:
        """Read a file from the container."""
        cid = self.context.container_id
        if not cid:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "head", "-c", "65536", fpath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return ""
            return stdout.decode(errors="replace")
        except Exception:
            return ""
