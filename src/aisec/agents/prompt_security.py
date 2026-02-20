"""Prompt security analysis agent -- injection, leakage, and hijacking."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known prompt injection patterns
# ---------------------------------------------------------------------------
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "Instruction override",
        "Attempts to override system instructions via 'ignore previous instructions'",
        re.compile(
            r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
        ),
    ),
    (
        "Role reassignment",
        "Attempts to reassign the AI role via 'you are now' or 'act as'",
        re.compile(
            r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as)",
        ),
    ),
    (
        "System prompt extraction",
        "Attempts to extract the system prompt",
        re.compile(
            r"(?i)(repeat|show|print|display|reveal|output|tell\s+me)\s+"
            r"(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+prompt|rules)",
        ),
    ),
    (
        "Delimiter injection",
        "Uses special delimiters to escape prompt context",
        re.compile(
            r"```system|<\|system\|>|<\|im_start\|>|<<SYS>>|\[INST\]|\[/INST\]",
        ),
    ),
    (
        "Encoding evasion",
        "Uses base64 or other encoding to bypass filters",
        re.compile(
            r"(?i)(base64|rot13|hex|url)\s*(encode|decode|encoded|decoded)",
        ),
    ),
    (
        "Tool call injection",
        "Attempts to inject tool/function calls",
        re.compile(
            r"(?i)(call\s+function|execute\s+tool|run\s+command|invoke\s+api|<tool_call>|<function>)",
        ),
    ),
    (
        "DAN jailbreak",
        "Attempts the 'Do Anything Now' jailbreak pattern",
        re.compile(
            r"(?i)(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)",
        ),
    ),
    (
        "Indirect injection via data",
        "Hidden instructions in data fields that the agent may process",
        re.compile(
            r"(?i)(IMPORTANT:\s*ignore|SYSTEM:\s*override|HIDDEN\s*INSTRUCTION|AI:\s*execute)",
        ),
    ),
]

# Patterns that indicate input validation / sanitization
VALIDATION_PATTERNS = [
    re.compile(r"(?i)(input[_\s]?valid|sanitiz|escape|filter[_\s]?input|clean[_\s]?input)"),
    re.compile(r"(?i)(content[_\s]?polic|moderat|guardrail|safety[_\s]?filter)"),
    re.compile(r"(?i)(prompt[_\s]?injection|injection[_\s]?detect|input[_\s]?guard)"),
    re.compile(r"(?i)(allow[_\s]?list|deny[_\s]?list|block[_\s]?list|whitelist|blacklist)"),
]


class PromptSecurityAgent(BaseAgent):
    """Analyse prompt injection risks, system prompt leakage, and tool hijacking."""

    name: ClassVar[str] = "prompt_security"
    description: ClassVar[str] = (
        "Checks for prompt injection vulnerabilities, system prompt "
        "leakage vectors, tool hijacking possibilities, and input "
        "validation controls."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM07", "ASI01", "ASI09"]
    depends_on: ClassVar[list[str]] = ["network"]

    async def analyze(self) -> None:
        """Run prompt security checks."""
        source_files = await self._collect_source_files()
        api_endpoints = await self._discover_api_endpoints()

        await self._check_injection_patterns(source_files, api_endpoints)
        await self._check_system_prompt_leakage(source_files)
        await self._check_tool_hijacking(source_files)
        await self._check_input_validation(source_files)

    # ------------------------------------------------------------------
    # Source file collection
    # ------------------------------------------------------------------

    async def _collect_source_files(self) -> dict[str, str]:
        """Gather source code from the container."""
        cid = self.context.container_id
        if not cid:
            return {}

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /app /src /opt -maxdepth 5 -type f "
                "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' "
                "-o -name '*.yaml' -o -name '*.yml' -o -name '*.json' "
                "-o -name '*.toml' \\) -size -512k 2>/dev/null | head -100",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            file_list = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return {}

        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "65536", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    contents[fpath] = stdout.decode(errors="replace")
            except Exception:
                continue
        return contents

    # ------------------------------------------------------------------
    # API endpoint discovery
    # ------------------------------------------------------------------

    async def _discover_api_endpoints(self) -> list[dict[str, Any]]:
        """Attempt to discover exposed API endpoints from the network agent results."""
        endpoints: list[dict[str, Any]] = []

        # Check network agent results for exposed ports
        network_result = self.context.agent_results.get("network")
        if network_result:
            for finding in network_result.findings:
                for ev in finding.evidence:
                    if ev.type == "config" and ev.raw_data:
                        try:
                            data = json.loads(ev.raw_data)
                            if "port" in data:
                                port_str = data["port"]
                                port_num = int(port_str.split("/")[0])
                                endpoints.append({
                                    "port": port_num,
                                    "protocol": port_str.split("/")[1] if "/" in port_str else "tcp",
                                })
                        except (json.JSONDecodeError, ValueError, KeyError):
                            pass

        # Also try to discover routes from source code
        cid = self.context.container_id
        if cid:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid,
                    "sh", "-c",
                    "grep -r -n '@app.\\(route\\|get\\|post\\|put\\|delete\\)\\|router.\\(get\\|post\\|put\\)\\|app.use' "
                    "/app /src /opt 2>/dev/null | head -30",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                routes = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
                if routes:
                    for line in routes.splitlines():
                        endpoints.append({"route_definition": line.strip()})
            except Exception:
                pass

        return endpoints

    # ------------------------------------------------------------------
    # Prompt injection pattern checks
    # ------------------------------------------------------------------

    async def _check_injection_patterns(
        self,
        source_files: dict[str, str],
        api_endpoints: list[dict[str, Any]],
    ) -> None:
        """Check if the agent's code or data contains prompt injection patterns."""
        # Scan source code for injection test cases or embedded injection strings
        hits: list[tuple[str, str, str]] = []  # (pattern_name, file, match)

        for fpath, content in source_files.items():
            for pattern_name, description, regex in INJECTION_PATTERNS:
                matches = regex.findall(content)
                if matches:
                    for m in matches[:3]:
                        match_str = m if isinstance(m, str) else m[0] if m else ""
                        hits.append((pattern_name, fpath, match_str))

        if hits:
            # Distinguish: are these defensive (test patterns) or vulnerabilities?
            test_related = any(
                "test" in fpath.lower() or "spec" in fpath.lower()
                for _, fpath, _ in hits
            )

            details = "\n".join(
                f"  [{name}] {fpath}: '{match[:60]}'"
                for name, fpath, match in hits[:20]
            )

            if test_related:
                self.add_finding(
                    title="Prompt injection test patterns found",
                    description=(
                        f"Found {len(hits)} prompt injection pattern(s) in test files. "
                        "This indicates the application has prompt injection test "
                        "coverage, which is a positive security practice."
                    ),
                    severity=Severity.INFO,
                    owasp_llm=["LLM01"],
                    owasp_agentic=["ASI01"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary="Injection patterns in test files",
                            raw_data=details,
                            location=f"container:{self.context.container_id}",
                        )
                    ],
                    remediation="Continue expanding prompt injection test coverage.",
                )
            else:
                self.add_finding(
                    title="Prompt injection patterns found in source code",
                    description=(
                        f"Found {len(hits)} prompt injection pattern(s) in "
                        "non-test source files. These may be example payloads, "
                        "training data, or indicate that the application processes "
                        "user input without adequate sanitization against known "
                        "injection techniques."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM01"],
                    owasp_agentic=["ASI01", "ASI09"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"Injection patterns ({len(hits)} matches)",
                            raw_data=details,
                            location=f"container:{self.context.container_id}",
                        )
                    ],
                    remediation=(
                        "Implement prompt injection detection and filtering. "
                        "Use input validation, content moderation, and guardrails "
                        "to prevent known injection patterns from reaching the LLM. "
                        "Consider using a dedicated prompt firewall."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "https://simonwillison.net/2023/Apr/14/worst-that-can-happen/",
                    ],
                    cvss_score=8.0,
                    ai_risk_score=9.0,
                )

        # Check if API endpoints accept user input without injection protection
        if api_endpoints and not hits:
            has_routes = any("route_definition" in ep for ep in api_endpoints)
            if has_routes:
                self.add_finding(
                    title="API endpoints may be vulnerable to prompt injection",
                    description=(
                        "The agent exposes API endpoints that likely accept user "
                        "input, but no prompt injection patterns or defenses were "
                        "detected in the source code. Without active injection "
                        "detection, user input may manipulate the agent's behavior."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM01"],
                    owasp_agentic=["ASI01"],
                    evidence=[
                        Evidence(
                            type="api_response",
                            summary="API route definitions",
                            raw_data=json.dumps(api_endpoints[:10], default=str),
                            location=f"container:{self.context.container_id}",
                        )
                    ],
                    remediation=(
                        "Add prompt injection detection and filtering for all "
                        "user-facing API endpoints. Implement input validation "
                        "and consider rate limiting to mitigate automated attacks."
                    ),
                    cvss_score=6.5,
                    ai_risk_score=7.5,
                )

    # ------------------------------------------------------------------
    # System prompt leakage
    # ------------------------------------------------------------------

    async def _check_system_prompt_leakage(self, source_files: dict[str, str]) -> None:
        """Check for system prompt leakage vectors."""
        system_prompt_patterns = [
            re.compile(r'(?i)system[_\s]?prompt\s*[:=]\s*["\']'),
            re.compile(r'(?i)system[_\s]?message\s*[:=]\s*["\']'),
            re.compile(r'(?i)\{["\']role["\']\s*:\s*["\']system["\']'),
            re.compile(r'(?i)SYSTEM_PROMPT\s*='),
            re.compile(r'(?i)instructions?\s*[:=]\s*"""'),
        ]

        hardcoded_prompts: list[tuple[str, str]] = []

        for fpath, content in source_files.items():
            for pattern in system_prompt_patterns:
                matches = pattern.finditer(content)
                for m in matches:
                    # Extract a snippet around the match
                    start = max(0, m.start() - 20)
                    end = min(len(content), m.end() + 200)
                    snippet = content[start:end].strip()
                    hardcoded_prompts.append((fpath, snippet))

        if not hardcoded_prompts:
            return

        # Check if the prompt is exposed through error messages or API responses
        leakage_risks = []
        for fpath, content in source_files.items():
            if re.search(r"(?i)(traceback|stack.?trace|exception|error.?message)", content):
                if any(pp[0] == fpath for pp in hardcoded_prompts):
                    leakage_risks.append(fpath)

        details = "\n".join(
            f"  {fpath}: {snippet[:100]}..."
            for fpath, snippet in hardcoded_prompts[:10]
        )

        severity = Severity.HIGH if leakage_risks else Severity.MEDIUM
        self.add_finding(
            title="System prompt hardcoded in source files",
            description=(
                f"Found {len(hardcoded_prompts)} hardcoded system prompt(s) in "
                "source files. Hardcoded system prompts can be extracted through "
                "prompt injection attacks, error messages, or by inspecting the "
                "container image layers."
                + (
                    f" Additionally, {len(leakage_risks)} file(s) containing system "
                    "prompts also handle exceptions, increasing the risk of "
                    "leakage through error messages."
                    if leakage_risks else ""
                )
            ),
            severity=severity,
            owasp_llm=["LLM07"],
            owasp_agentic=["ASI01"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"{len(hardcoded_prompts)} hardcoded system prompts",
                    raw_data=details,
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Store system prompts in environment variables or a secrets "
                "manager rather than hardcoding them. Implement error handling "
                "that does not expose system prompts in error messages. Use "
                "prompt obfuscation techniques for defense-in-depth."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=6.0,
            ai_risk_score=7.0,
        )

    # ------------------------------------------------------------------
    # Tool hijacking
    # ------------------------------------------------------------------

    async def _check_tool_hijacking(self, source_files: dict[str, str]) -> None:
        """Check for tool hijacking vulnerabilities."""
        tool_patterns = [
            re.compile(r'(?i)(tool|function)[_\s]?(call|invoke|execute|run)'),
            re.compile(r'(?i)@tool\b'),
            re.compile(r'(?i)tools?\s*[:=]\s*\['),
            re.compile(r'(?i)(langchain|autogen|crewai|openai).*tool'),
            re.compile(r'(?i)function[_\s]?calling'),
        ]

        tool_files: list[tuple[str, str]] = []
        for fpath, content in source_files.items():
            for pattern in tool_patterns:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 150)
                    tool_files.append((fpath, content[start:end].strip()))
                    break  # one match per file is enough

        if not tool_files:
            return

        # Check for tool authorization / confirmation patterns
        auth_patterns = [
            re.compile(r'(?i)(confirm|approve|authorize|permission|human.?in.?the.?loop)'),
            re.compile(r'(?i)(require.?approval|ask.?user|user.?confirm)'),
            re.compile(r'(?i)(tool.?guard|tool.?filter|allowed.?tools)'),
        ]

        has_authorization = False
        for fpath, content in source_files.items():
            for ap in auth_patterns:
                if ap.search(content):
                    has_authorization = True
                    break
            if has_authorization:
                break

        details = "\n".join(
            f"  {fpath}: {snippet[:120]}..."
            for fpath, snippet in tool_files[:10]
        )

        if not has_authorization:
            self.add_finding(
                title="Tool/function calling without authorization controls",
                description=(
                    f"The agent uses tool/function calling (found in {len(tool_files)} "
                    "file(s)) but no authorization, confirmation, or human-in-the-loop "
                    "controls were detected. A prompt injection attack could hijack "
                    "the agent's tools to perform unauthorized actions such as data "
                    "exfiltration, code execution, or API abuse."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM01", "LLM07"],
                owasp_agentic=["ASI01", "ASI09"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Tool calling in {len(tool_files)} files, no auth controls",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement tool authorization controls: require explicit user "
                    "confirmation for sensitive operations, use an allow-list of "
                    "permitted tools, and add human-in-the-loop approval for "
                    "high-risk actions. Apply the principle of least privilege to "
                    "tool access."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=9.0,
                ai_risk_score=9.5,
            )
        else:
            self.add_finding(
                title="Tool/function calling with some authorization controls",
                description=(
                    f"The agent uses tool/function calling (found in {len(tool_files)} "
                    "file(s)) and has some authorization or confirmation controls. "
                    "Verify that these controls are consistently applied to all "
                    "tool invocations and cannot be bypassed through prompt injection."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI01"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Tool calling with auth controls",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Ensure authorization controls are applied consistently to all "
                    "tool invocations. Test that prompt injection cannot bypass "
                    "these controls."
                ),
                cvss_score=3.0,
                ai_risk_score=4.0,
            )

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    async def _check_input_validation(self, source_files: dict[str, str]) -> None:
        """Check whether input validation and sanitization is implemented."""
        validation_hits: list[str] = []

        for fpath, content in source_files.items():
            for pattern in VALIDATION_PATTERNS:
                if pattern.search(content):
                    validation_hits.append(fpath)
                    break

        if not validation_hits:
            self.add_finding(
                title="No input validation or sanitization detected",
                description=(
                    "No input validation, sanitization, content moderation, or "
                    "guardrail mechanisms were detected in the agent's source code. "
                    "Without input validation, the agent is vulnerable to prompt "
                    "injection, adversarial inputs, and other input manipulation attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI01", "ASI09"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No validation patterns found",
                        raw_data=f"Searched {len(source_files)} source files for validation patterns",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement input validation and sanitization for all user inputs. "
                    "Consider using: (1) regex-based input filtering, (2) content "
                    "moderation APIs, (3) prompt injection detection models, "
                    "(4) guardrail frameworks (e.g., NeMo Guardrails, Guardrails AI). "
                    "Apply defense-in-depth with multiple validation layers."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=7.0,
                ai_risk_score=8.0,
            )
        else:
            self.add_finding(
                title="Input validation mechanisms detected",
                description=(
                    f"Input validation or sanitization was found in "
                    f"{len(validation_hits)} file(s). Verify that validation is "
                    "applied to all user input paths and covers known prompt "
                    "injection techniques."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI01"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Validation in {len(validation_hits)} files",
                        raw_data="\n".join(f"  {f}" for f in validation_hits[:20]),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Continue expanding validation coverage. Ensure all user input "
                    "paths are protected and test against known injection techniques."
                ),
            )
