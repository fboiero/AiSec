"""Permission and privilege analysis agent."""

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

# Docker capabilities considered dangerous
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN": (
        Severity.CRITICAL,
        "Grants a wide range of admin operations including mount, "
        "ptrace, and namespace manipulation. Effectively root-equivalent.",
    ),
    "NET_ADMIN": (
        Severity.HIGH,
        "Allows network configuration changes including firewall rules, "
        "routing tables, and interface configuration.",
    ),
    "SYS_PTRACE": (
        Severity.HIGH,
        "Allows tracing and debugging other processes, enabling memory "
        "inspection and code injection.",
    ),
    "NET_RAW": (
        Severity.MEDIUM,
        "Allows raw socket creation for packet sniffing and spoofing.",
    ),
    "DAC_OVERRIDE": (
        Severity.HIGH,
        "Bypasses file read/write/execute permission checks.",
    ),
    "SYS_MODULE": (
        Severity.CRITICAL,
        "Allows loading and unloading kernel modules -- full host compromise.",
    ),
    "SYS_RAWIO": (
        Severity.CRITICAL,
        "Allows raw I/O port access -- can read/write hardware directly.",
    ),
    "MKNOD": (
        Severity.MEDIUM,
        "Allows creation of special device files.",
    ),
    "SETUID": (
        Severity.MEDIUM,
        "Allows setting the UID of a process.",
    ),
    "SETGID": (
        Severity.MEDIUM,
        "Allows setting the GID of a process.",
    ),
    "AUDIT_WRITE": (
        Severity.LOW,
        "Allows writing to the kernel audit log.",
    ),
}

# Patterns indicating unrestricted shell/command execution in code
SHELL_EXEC_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "subprocess call",
        re.compile(r"subprocess\.(call|run|Popen|check_output|check_call)\s*\("),
        "Python subprocess module used for shell command execution",
    ),
    (
        "os.system",
        re.compile(r"os\.system\s*\("),
        "os.system() executes shell commands with full shell interpretation",
    ),
    (
        "os.popen",
        re.compile(r"os\.popen\s*\("),
        "os.popen() opens a pipe to a shell command",
    ),
    (
        "exec/eval",
        re.compile(r"(?<!def )\b(exec|eval)\s*\("),
        "exec()/eval() allows arbitrary code execution",
    ),
    (
        "child_process",
        re.compile(r"(?:child_process|execSync|spawnSync|execFile)\s*[\.(]"),
        "Node.js child_process module for shell command execution",
    ),
    (
        "shell=True",
        re.compile(r"shell\s*=\s*True"),
        "shell=True enables full shell interpretation, vulnerable to injection",
    ),
]

# Tool/skill risk classifications
TOOL_RISK_KEYWORDS: dict[str, tuple[Severity, str]] = {
    "file": (Severity.MEDIUM, "File system access"),
    "read_file": (Severity.MEDIUM, "File read access"),
    "write_file": (Severity.HIGH, "File write access"),
    "delete": (Severity.HIGH, "Deletion capability"),
    "execute": (Severity.CRITICAL, "Code/command execution"),
    "shell": (Severity.CRITICAL, "Shell access"),
    "bash": (Severity.CRITICAL, "Bash shell access"),
    "terminal": (Severity.CRITICAL, "Terminal access"),
    "http": (Severity.MEDIUM, "HTTP request capability"),
    "request": (Severity.MEDIUM, "Network request capability"),
    "database": (Severity.HIGH, "Database access"),
    "sql": (Severity.HIGH, "SQL query capability"),
    "email": (Severity.MEDIUM, "Email sending capability"),
    "deploy": (Severity.CRITICAL, "Deployment capability"),
    "admin": (Severity.CRITICAL, "Administrative operations"),
    "root": (Severity.CRITICAL, "Root-level access"),
    "sudo": (Severity.CRITICAL, "Sudo privilege escalation"),
    "api": (Severity.MEDIUM, "External API access"),
    "secret": (Severity.HIGH, "Secrets management access"),
    "credential": (Severity.HIGH, "Credential access"),
    "payment": (Severity.CRITICAL, "Payment processing"),
    "transfer": (Severity.HIGH, "Data/fund transfer"),
}


class PermissionAgent(BaseAgent):
    """Analyse container permissions, capabilities, and agent tool access."""

    name: ClassVar[str] = "permission"
    description: ClassVar[str] = (
        "Checks container privilege level, Docker capabilities, shell access, "
        "tool/skill enumeration, and human-in-the-loop controls."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM06", "ASI02", "ASI03", "ASI10"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run all permission and privilege checks."""
        container_info = await self._get_container_info()

        await self._check_running_as_root(container_info)
        await self._check_shell_access()
        await self._check_capabilities(container_info)
        await self._check_tool_enumeration()
        await self._check_human_in_the_loop()

    # ------------------------------------------------------------------
    # Container info
    # ------------------------------------------------------------------

    async def _get_container_info(self) -> dict[str, Any]:
        """Retrieve container inspect data."""
        cid = self.context.container_id
        if not cid:
            return {}

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            data = json.loads(stdout.decode(errors="replace"))
            return data[0] if isinstance(data, list) else data
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Root user check
    # ------------------------------------------------------------------

    async def _check_running_as_root(self, info: dict[str, Any]) -> None:
        """Check if the container process runs as root."""
        cid = self.context.container_id
        if not cid:
            return

        # Check Config.User
        config_user = info.get("Config", {}).get("User", "")

        # Also check the actual running user
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "id",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            id_output = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            id_output = ""

        is_root = False
        if not config_user or config_user in ("0", "root"):
            is_root = True
        if "uid=0" in id_output:
            is_root = True

        # Check for privileged mode
        privileged = info.get("HostConfig", {}).get("Privileged", False)

        if privileged:
            self.add_finding(
                title="Container running in privileged mode",
                description=(
                    "The container is running with --privileged flag, granting "
                    "full access to host devices and bypassing all security "
                    "mechanisms. A compromised AI agent in privileged mode can "
                    "fully compromise the host system."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03", "ASI10"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Privileged mode enabled",
                        raw_data=json.dumps({
                            "Privileged": True,
                            "User": config_user,
                            "id_output": id_output,
                        }),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "NEVER run AI agent containers in privileged mode. Remove the "
                    "--privileged flag and grant only the specific capabilities "
                    "the agent requires (if any). Use --cap-drop ALL and "
                    "selectively add needed capabilities."
                ),
                cvss_score=10.0,
                ai_risk_score=10.0,
            )
        elif is_root:
            self.add_finding(
                title="Container process running as root",
                description=(
                    f"The container process runs as root (user='{config_user or 'root'}', "
                    f"id output: '{id_output}'). Running as root inside a container "
                    "increases the risk of container escape and grants unnecessary "
                    "privileges to the AI agent process."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Running as root",
                        raw_data=json.dumps({
                            "User": config_user,
                            "id_output": id_output,
                        }),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Add a non-root USER directive to the Dockerfile. Use "
                    "'docker run --user <uid>:<gid>' to run as a non-privileged "
                    "user. Ensure file permissions allow the non-root user to "
                    "operate correctly."
                ),
                cvss_score=7.0,
                ai_risk_score=7.5,
            )

    # ------------------------------------------------------------------
    # Shell access detection
    # ------------------------------------------------------------------

    async def _check_shell_access(self) -> None:
        """Check for unrestricted shell/command execution in source code."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /app /src /opt -maxdepth 5 -type f "
                "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' \\) "
                "-size -512k 2>/dev/null | head -80",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            file_list = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return

        hits: list[tuple[str, str, str]] = []  # (pattern_name, file, snippet)

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
                if proc.returncode != 0:
                    continue
                content = stdout.decode(errors="replace")
            except Exception:
                continue

            for pattern_name, regex, _desc in SHELL_EXEC_PATTERNS:
                matches = list(regex.finditer(content))
                for m in matches[:3]:
                    start = max(0, m.start() - 30)
                    end = min(len(content), m.end() + 60)
                    snippet = content[start:end].strip().replace("\n", " ")
                    hits.append((pattern_name, fpath, snippet))

        if not hits:
            return

        details = "\n".join(
            f"  [{name}] {fpath}: {snippet[:100]}"
            for name, fpath, snippet in hits[:20]
        )

        # Check if shell=True is used (extra dangerous)
        has_shell_true = any(name == "shell=True" for name, _, _ in hits)
        has_exec_eval = any(name == "exec/eval" for name, _, _ in hits)

        severity = Severity.CRITICAL if (has_shell_true or has_exec_eval) else Severity.HIGH

        self.add_finding(
            title=f"Unrestricted shell/code execution detected ({len(hits)} instances)",
            description=(
                f"Found {len(hits)} instance(s) of shell command execution or "
                "dynamic code evaluation in the agent's source code."
                + (" Includes shell=True which allows shell injection." if has_shell_true else "")
                + (" Includes exec()/eval() for arbitrary code execution." if has_exec_eval else "")
                + " If the AI agent can be manipulated through prompt injection to "
                "invoke these code paths, it could lead to remote code execution "
                "on the container (or host in privileged mode)."
            ),
            severity=severity,
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI02", "ASI03", "ASI10"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Shell/exec patterns ({len(hits)} matches)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Replace shell=True with explicit command lists. Avoid exec() and "
                "eval() -- use safe alternatives. Implement a sandboxed execution "
                "environment for any necessary code execution. Apply strict input "
                "validation before any command construction. Use --read-only "
                "filesystem and seccomp profiles to limit damage."
            ),
            cvss_score=9.0 if severity == Severity.CRITICAL else 7.5,
            ai_risk_score=9.0,
        )

    # ------------------------------------------------------------------
    # Docker capability analysis
    # ------------------------------------------------------------------

    async def _check_capabilities(self, info: dict[str, Any]) -> None:
        """Analyse Docker capabilities granted to the container."""
        host_config = info.get("HostConfig", {})
        cap_add: list[str] = host_config.get("CapAdd") or []
        cap_drop: list[str] = host_config.get("CapDrop") or []

        # Get effective capabilities from the running process
        cid = self.context.container_id
        effective_caps: str = ""
        if cid:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid,
                    "sh", "-c",
                    "cat /proc/1/status 2>/dev/null | grep -i cap",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                effective_caps = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
            except Exception:
                pass

        dangerous_found: list[tuple[str, Severity, str]] = []
        for cap in cap_add:
            cap_upper = cap.upper()
            if cap_upper in DANGEROUS_CAPABILITIES:
                sev, desc = DANGEROUS_CAPABILITIES[cap_upper]
                dangerous_found.append((cap_upper, sev, desc))

        # Check if ALL capabilities are dropped (best practice)
        all_dropped = "ALL" in [c.upper() for c in cap_drop]

        if dangerous_found:
            details = "\n".join(
                f"  {cap} ({sev.value}): {desc}"
                for cap, sev, desc in dangerous_found
            )
            worst_severity = min(
                (sev for _, sev, _ in dangerous_found),
                key=lambda s: list(Severity).index(s),
            )
            self.add_finding(
                title=f"Dangerous Docker capabilities granted ({len(dangerous_found)})",
                description=(
                    f"The container has {len(dangerous_found)} dangerous "
                    "capability(ies) granted. These capabilities expand the "
                    "container's attack surface and may enable container escape "
                    "or host compromise if the AI agent is compromised."
                ),
                severity=worst_severity,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03", "ASI10"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Dangerous capabilities",
                        raw_data=details,
                        location=f"container:{cid}",
                    ),
                    Evidence(
                        type="config",
                        summary="Effective process capabilities",
                        raw_data=effective_caps or "Could not read",
                        location=f"container:{cid}",
                    ),
                ],
                remediation=(
                    "Use --cap-drop ALL and only add the specific capabilities "
                    "required by the application. Most AI agent containers do "
                    "not need any additional capabilities."
                ),
                cvss_score=8.5,
                ai_risk_score=8.0,
            )

        if not all_dropped and not dangerous_found:
            self.add_finding(
                title="Default Docker capabilities not explicitly dropped",
                description=(
                    "The container retains the default Docker capabilities. "
                    "While not as dangerous as explicitly added capabilities, "
                    "best practice is to drop all capabilities and add only "
                    "what is needed."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Default capabilities retained",
                        raw_data=json.dumps({
                            "CapAdd": cap_add,
                            "CapDrop": cap_drop,
                        }),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Add --cap-drop ALL to the container run command and "
                    "selectively add only required capabilities."
                ),
                cvss_score=3.0,
            )

    # ------------------------------------------------------------------
    # Tool / skill enumeration
    # ------------------------------------------------------------------

    async def _check_tool_enumeration(self) -> None:
        """Enumerate agent tools/skills and classify their risk."""
        cid = self.context.container_id
        if not cid:
            return

        # Search for tool definitions in source code
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "grep -r -n "
                "'@tool\\|def tool_\\|\"name\".*\"tool\\|tools.*=.*\\[\\|"
                "register_tool\\|add_tool\\|ToolDefinition\\|BaseTool\\|"
                "FunctionTool\\|StructuredTool' "
                "/app /src /opt 2>/dev/null | head -50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            tool_defs = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            tool_defs = ""

        if not tool_defs:
            return

        # Classify tools by risk level
        high_risk_tools: list[str] = []
        medium_risk_tools: list[str] = []

        for line in tool_defs.splitlines():
            line_lower = line.lower()
            for keyword, (severity, label) in TOOL_RISK_KEYWORDS.items():
                if keyword in line_lower:
                    entry = f"{line.strip()[:120]} -- {label}"
                    if severity in (Severity.CRITICAL, Severity.HIGH):
                        high_risk_tools.append(entry)
                    else:
                        medium_risk_tools.append(entry)
                    break

        if high_risk_tools:
            self.add_finding(
                title=f"High-risk agent tools detected ({len(high_risk_tools)})",
                description=(
                    f"Found {len(high_risk_tools)} high-risk tool(s) available "
                    "to the AI agent. These tools provide capabilities (shell "
                    "access, file writes, database access, etc.) that could "
                    "cause significant damage if misused through prompt injection "
                    "or agent goal hijacking."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(high_risk_tools)} high-risk tools",
                        raw_data="\n".join(high_risk_tools[:20]),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Apply the principle of least privilege to agent tools. "
                    "Remove tools that are not strictly necessary. Implement "
                    "authorization controls and rate limiting for high-risk "
                    "tools. Add human-in-the-loop approval for destructive "
                    "operations."
                ),
                cvss_score=7.0,
                ai_risk_score=8.0,
            )

        if medium_risk_tools:
            self.add_finding(
                title=f"Medium-risk agent tools detected ({len(medium_risk_tools)})",
                description=(
                    f"Found {len(medium_risk_tools)} medium-risk tool(s) "
                    "available to the AI agent."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(medium_risk_tools)} medium-risk tools",
                        raw_data="\n".join(medium_risk_tools[:20]),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Review medium-risk tools for necessity. Apply input "
                    "validation and output filtering to each tool."
                ),
                cvss_score=5.0,
            )

    # ------------------------------------------------------------------
    # Human-in-the-loop controls
    # ------------------------------------------------------------------

    async def _check_human_in_the_loop(self) -> None:
        """Check for human-in-the-loop control mechanisms."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "grep -r -i -l "
                "'human.in.the.loop\\|human_approval\\|user_confirm\\|"
                "require_approval\\|manual_review\\|approval_required\\|"
                "confirm_action\\|ask_permission\\|supervision\\|"
                "breakpoint\\|pause_for_human' "
                "/app /src /opt 2>/dev/null | head -10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            hitl_files = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            hitl_files = ""

        if not hitl_files:
            self.add_finding(
                title="No human-in-the-loop controls detected",
                description=(
                    "No human-in-the-loop (HITL) control mechanisms were found "
                    "in the agent's source code. Without HITL controls, the AI "
                    "agent operates fully autonomously with no human oversight "
                    "for high-risk actions. This increases the impact of prompt "
                    "injection, goal hijacking, and cascading failures."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03", "ASI10"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No HITL patterns found",
                        raw_data=f"Searched source files in container:{cid}",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Implement human-in-the-loop controls for high-risk operations. "
                    "Require explicit human approval before: executing commands, "
                    "modifying files, making API calls, or taking irreversible "
                    "actions. Use a tiered autonomy model where the agent can act "
                    "independently for low-risk tasks but requires approval for "
                    "high-risk ones."
                ),
                cvss_score=6.0,
                ai_risk_score=8.0,
            )
        else:
            hitl_list = hitl_files.splitlines()
            self.add_finding(
                title=f"Human-in-the-loop controls present ({len(hitl_list)} files)",
                description=(
                    f"Human-in-the-loop control patterns were found in "
                    f"{len(hitl_list)} file(s). Verify that these controls "
                    "are applied to all high-risk agent operations and cannot "
                    "be bypassed through prompt manipulation."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI10"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="HITL control files",
                        raw_data="\n".join(f"  {f}" for f in hitl_list),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Ensure HITL controls cover all high-risk operations and "
                    "test that they cannot be bypassed through prompt injection."
                ),
            )
