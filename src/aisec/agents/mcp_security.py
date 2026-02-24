"""Model Context Protocol (MCP) security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# MCP server framework patterns
MCP_SERVER_PATTERNS = re.compile(
    r'(?:mcp\.server\.Server|McpServer|from\s+mcp\s+import|'
    r'from\s+mcp\.server|@server\.tool|@mcp\.tool|'
    r'StdioServerTransport|SSEServerTransport|'
    r'StreamableHTTPServer|FastMCP)',
)

# MCP auth patterns
MCP_AUTH_PATTERNS = re.compile(
    r'(?:@server\.auth|auth_handler|authenticate|api_key.*verify|'
    r'bearer.*token|check_auth|verify_token|auth_middleware|'
    r'require_auth|AuthHandler|APIKeyAuth)',
    re.IGNORECASE,
)

# MCP tool decorator patterns
MCP_TOOL_PATTERNS = re.compile(
    r'@(?:server\.tool|mcp\.tool|app\.tool)\s*\(',
)

# Tool input validation patterns (Annotated, Field, constraints)
TOOL_VALIDATION_PATTERNS = re.compile(
    r'(?:Annotated\[|Field\s*\(|max_length|min_length|pattern=|'
    r'regex=|enum=|le=|ge=|gt=|lt=|Literal\[|constr\(|'
    r'validator|field_validator)',
    re.IGNORECASE,
)

# Tool allowlist / filter patterns
TOOL_ALLOWLIST_PATTERNS = re.compile(
    r'(?:allowed_tools|tool_filter|tool_allowlist|tool_whitelist|'
    r'enabled_tools|tool_permissions|restrict_tools|tool_access)',
    re.IGNORECASE,
)

# Transport patterns
HTTP_TRANSPORT_PATTERNS = re.compile(
    r'(?:transport\s*=\s*["\'](?:http|sse)["\']|'
    r'host\s*=\s*["\']0\.0\.0\.0["\']|'
    r'SSEServerTransport|StreamableHTTPServer|'
    r'port\s*=\s*\d+)',
    re.IGNORECASE,
)

TLS_PATTERNS = re.compile(
    r'(?:ssl|tls|https|cert|certificate|ssl_context|'
    r'keyfile|certfile|ssl_keyfile|ssl_certfile)',
    re.IGNORECASE,
)

# Rate limiting patterns
RATE_LIMIT_PATTERNS = re.compile(
    r'(?:rate_limit|ratelimit|throttle|slowapi|'
    r'RateLimiter|max_requests|requests_per)',
    re.IGNORECASE,
)

# Sensitive tool operations
SENSITIVE_TOOL_OPS = re.compile(
    r'(?:exec\s*\(|eval\s*\(|subprocess|os\.system|os\.popen|'
    r'open\s*\(.*["\']w|write_file|delete_file|remove\s*\(|'
    r'unlink|rmtree|execute_sql|cursor\.execute|'
    r'send_email|smtp|http_request|requests\.(get|post|put|delete)|'
    r'shutil\.rmtree|os\.remove)',
    re.IGNORECASE,
)

# Approval / HITL patterns
APPROVAL_PATTERNS = re.compile(
    r'(?:require_approval|human_in_the_loop|confirm|approval|'
    r'ask_user|user_confirm|hitl|human_review|'
    r'await.*confirm|require_confirmation)',
    re.IGNORECASE,
)

# Resource URI patterns
RESOURCE_URI_PATTERNS = re.compile(
    r'@(?:server\.resource|mcp\.resource|app\.resource)\s*\(',
)

# Path traversal protection
PATH_VALIDATION_PATTERNS = re.compile(
    r'(?:resolve\(\)|realpath|abspath|os\.path\.normpath|'
    r'startswith.*base|sanitize.*path|validate.*path|'
    r'pathlib.*resolve|is_relative_to)',
    re.IGNORECASE,
)

# Tool output sanitization
OUTPUT_SANITIZATION_PATTERNS = re.compile(
    r'(?:sanitize.*output|clean.*response|filter.*output|'
    r'escape.*html|strip.*tags|output_filter|'
    r'validate.*return|safe_output)',
    re.IGNORECASE,
)

# Secret patterns in config files
MCP_SECRET_PATTERNS = re.compile(
    r'''(?:api_key|password|secret|token|auth_token|'''
    r'''private_key|access_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-/+]{16,}['\"]''',
    re.IGNORECASE,
)

# Debug / inspector patterns
MCP_DEBUG_PATTERNS = re.compile(
    r'(?:debug\s*=\s*True|inspector\s*=\s*True|'
    r'mcp.*inspector|mcp.*debug|verbose\s*=\s*True|'
    r'log_level.*DEBUG|enable_inspector)',
    re.IGNORECASE,
)


class MCPSecurityAgent(BaseAgent):
    """Audits Model Context Protocol server security."""

    name: ClassVar[str] = "mcp_security"
    description: ClassVar[str] = (
        "Audits Model Context Protocol server configurations, tool schemas, "
        "transport security, approval flows, and resource URI validation."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["ASI01", "ASI02", "LLM06"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze MCP server security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for MCP analysis",
                description="No source files found in the container.",
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

        # Only run checks if MCP patterns are detected
        if not MCP_SERVER_PATTERNS.search(combined):
            return

        self._check_unauthenticated_server(all_content, combined)
        self._check_permissive_schemas(all_content, combined)
        self._check_unrestricted_access(combined)
        self._check_insecure_transport(all_content, combined)
        self._check_rate_limiting(combined)
        self._check_missing_approval(all_content, combined)
        self._check_resource_path_traversal(all_content, combined)
        self._check_output_sanitization(all_content, combined)
        self._check_secrets_in_config(all_content)
        self._check_debug_endpoints(all_content, combined)

    def _check_unauthenticated_server(self, files: dict[str, str], combined: str) -> None:
        """Check for MCP servers without authentication."""
        has_server = bool(MCP_SERVER_PATTERNS.search(combined))
        has_auth = bool(MCP_AUTH_PATTERNS.search(combined))

        if has_server and not has_auth:
            self.add_finding(
                title="Unauthenticated MCP server",
                description=(
                    "MCP server detected without authentication middleware. "
                    "Any client can connect and invoke tools, potentially "
                    "executing dangerous operations."
                ),
                severity=Severity.CRITICAL,
                owasp_agentic=["ASI01", "ASI02"],
                owasp_llm=["LLM06"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Add authentication to the MCP server. Implement an auth handler "
                    "that validates API keys or Bearer tokens before allowing tool access."
                ),
                cvss_score=9.0,
                ai_risk_score=9.0,
            )

    def _check_permissive_schemas(self, files: dict[str, str], combined: str) -> None:
        """Check for tool schemas without input constraints."""
        for fpath, content in files.items():
            tool_matches = list(MCP_TOOL_PATTERNS.finditer(content))
            if not tool_matches:
                continue

            has_validation = bool(TOOL_VALIDATION_PATTERNS.search(content))
            if not has_validation:
                lines = [str(content[:m.start()].count("\n") + 1) for m in tool_matches]
                self.add_finding(
                    title="Overly permissive MCP tool schemas",
                    description=(
                        f"MCP tool(s) at {fpath} (lines: {', '.join(lines)}) "
                        "lack input validation constraints. Tool parameters accept "
                        "arbitrary strings without length limits or pattern matching."
                    ),
                    severity=Severity.HIGH,
                    owasp_agentic=["ASI02"],
                    owasp_llm=["LLM06"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Permissive tool schemas at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add input constraints using Annotated types with Field(): "
                        "Annotated[str, Field(max_length=1000, pattern=r'^[a-zA-Z]+$')]"
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_unrestricted_access(self, combined: str) -> None:
        """Check for no tool allowlist or access control."""
        has_tools = bool(MCP_TOOL_PATTERNS.search(combined))
        has_allowlist = bool(TOOL_ALLOWLIST_PATTERNS.search(combined))

        if has_tools and not has_allowlist:
            self.add_finding(
                title="Unrestricted MCP tool access",
                description=(
                    "MCP server exposes all registered tools to all clients "
                    "without an allowlist or permission filter. Clients can "
                    "invoke any tool regardless of their authorization level."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI02"],
                owasp_llm=["LLM06"],
                remediation=(
                    "Implement a tool allowlist or permission system. "
                    "Restrict tool access based on client identity or role."
                ),
                cvss_score=7.0,
                ai_risk_score=7.5,
            )

    def _check_insecure_transport(self, files: dict[str, str], combined: str) -> None:
        """Check for HTTP transport without TLS."""
        has_http = bool(HTTP_TRANSPORT_PATTERNS.search(combined))
        has_tls = bool(TLS_PATTERNS.search(combined))

        if has_http and not has_tls:
            self.add_finding(
                title="Insecure MCP transport: HTTP without TLS",
                description=(
                    "MCP server uses HTTP transport without TLS encryption. "
                    "Tool calls and responses are transmitted in plaintext, "
                    "exposing sensitive data to network interception."
                ),
                severity=Severity.HIGH,
                owasp_agentic=["ASI01"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Enable TLS for MCP HTTP transport. Use ssl_context or "
                    "deploy behind a TLS-terminating reverse proxy."
                ),
                cvss_score=7.5,
                ai_risk_score=6.0,
            )

    def _check_rate_limiting(self, combined: str) -> None:
        """Check for missing rate limiting on tool handlers."""
        has_tools = bool(MCP_TOOL_PATTERNS.search(combined))
        has_rate_limit = bool(RATE_LIMIT_PATTERNS.search(combined))

        if has_tools and not has_rate_limit:
            self.add_finding(
                title="No rate limiting on MCP tool calls",
                description=(
                    "MCP tool handlers lack rate limiting. A compromised or "
                    "misbehaving client could invoke tools at unlimited speed, "
                    "causing resource exhaustion or abuse."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                remediation=(
                    "Add rate limiting to the MCP server or individual tool handlers. "
                    "Limit requests per client per time window."
                ),
                cvss_score=5.0,
                ai_risk_score=5.0,
            )

    def _check_missing_approval(self, files: dict[str, str], combined: str) -> None:
        """Check for sensitive tools without approval flows."""
        for fpath, content in files.items():
            tool_matches = list(MCP_TOOL_PATTERNS.finditer(content))
            if not tool_matches:
                continue

            has_sensitive_ops = bool(SENSITIVE_TOOL_OPS.search(content))
            has_approval = bool(APPROVAL_PATTERNS.search(content))

            if has_sensitive_ops and not has_approval:
                self.add_finding(
                    title="Sensitive MCP tools without approval flow",
                    description=(
                        f"MCP tools at {fpath} perform sensitive operations "
                        "(file writes, code execution, network requests, database queries) "
                        "without human-in-the-loop approval."
                    ),
                    severity=Severity.HIGH,
                    owasp_agentic=["ASI02", "ASI01"],
                    owasp_llm=["LLM06"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Sensitive tools without approval at {fpath}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add require_approval=True for sensitive tools or implement "
                        "a human-in-the-loop confirmation step before executing "
                        "destructive operations."
                    ),
                    cvss_score=7.5,
                    ai_risk_score=8.0,
                )

    def _check_resource_path_traversal(self, files: dict[str, str], combined: str) -> None:
        """Check for resource URI handlers without path validation."""
        for fpath, content in files.items():
            resource_matches = list(RESOURCE_URI_PATTERNS.finditer(content))
            if not resource_matches:
                continue

            has_path_validation = bool(PATH_VALIDATION_PATTERNS.search(content))
            if not has_path_validation:
                lines = [str(content[:m.start()].count("\n") + 1) for m in resource_matches]
                self.add_finding(
                    title="MCP resource URI path traversal risk",
                    description=(
                        f"MCP resource handler(s) at {fpath} (lines: {', '.join(lines)}) "
                        "lack path validation. Clients could use ../ sequences to "
                        "access files outside the intended directory."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_agentic=["ASI02"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Resource handler without path validation at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Validate resource URIs: resolve the path and verify it starts with "
                        "the base directory using Path.resolve() and is_relative_to()."
                    ),
                    cvss_score=8.5,
                    ai_risk_score=8.0,
                )

    def _check_output_sanitization(self, files: dict[str, str], combined: str) -> None:
        """Check for tool outputs passed to LLM without sanitization."""
        has_tools = bool(MCP_TOOL_PATTERNS.search(combined))
        has_sanitization = bool(OUTPUT_SANITIZATION_PATTERNS.search(combined))

        if has_tools and not has_sanitization:
            self.add_finding(
                title="No MCP tool output sanitization",
                description=(
                    "MCP tool outputs are not sanitized before being passed to the LLM. "
                    "Tool results could contain injection payloads that manipulate "
                    "the LLM's behavior."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                remediation=(
                    "Sanitize tool outputs before returning to the LLM. Filter or "
                    "escape content that could be interpreted as instructions."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_secrets_in_config(self, files: dict[str, str]) -> None:
        """Check for secrets in MCP config files."""
        config_extensions = ('.json', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.env')
        for fpath, content in files.items():
            if not any(fpath.endswith(ext) for ext in config_extensions):
                continue

            if not re.search(r'(?:mcp|tool|server)', content, re.IGNORECASE):
                continue

            matches = list(MCP_SECRET_PATTERNS.finditer(content))
            if matches:
                lines = [str(content[:m.start()].count("\n") + 1) for m in matches]
                self.add_finding(
                    title="Secrets in MCP server configuration",
                    description=(
                        f"Hardcoded secrets found in MCP config at {fpath} "
                        f"(lines: {', '.join(lines)}). API keys and passwords "
                        "in config files can be extracted from containers."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_agentic=["ASI01"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Secrets in MCP config at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use environment variables or a secrets manager for MCP "
                        "server credentials. Never store secrets in config files."
                    ),
                    cvss_score=8.5,
                    ai_risk_score=7.0,
                )

    def _check_debug_endpoints(self, files: dict[str, str], combined: str) -> None:
        """Check for MCP debug/inspector endpoints in production."""
        for fpath, content in files.items():
            if not MCP_SERVER_PATTERNS.search(content):
                continue

            debug_matches = list(MCP_DEBUG_PATTERNS.finditer(content))
            if debug_matches:
                lines = [str(content[:m.start()].count("\n") + 1) for m in debug_matches]
                self.add_finding(
                    title="MCP debug/inspector endpoints enabled",
                    description=(
                        f"MCP debug or inspector mode enabled at {fpath} "
                        f"(lines: {', '.join(lines)}). Debug endpoints expose "
                        "server internals and tool schemas to unauthorized users."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_agentic=["ASI02"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Debug mode at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Disable debug mode and inspector in production. "
                        "Use environment-based configuration to toggle debug features."
                    ),
                    cvss_score=4.0,
                    ai_risk_score=4.0,
                )

    async def _collect_source_files(self) -> list[str]:
        """Collect source files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f "
            "\\( -name '*.py' -o -name '*.yaml' -o -name '*.yml' "
            "-o -name '*.json' -o -name '*.toml' -o -name '*.cfg' \\) "
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
