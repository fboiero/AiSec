"""Runtime behavior monitoring agent for sandbox execution analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Suspicious process patterns
SUSPICIOUS_PROCESSES = {
    "xmrig": (Severity.CRITICAL, "Cryptocurrency miner"),
    "minerd": (Severity.CRITICAL, "Cryptocurrency miner"),
    "cpuminer": (Severity.CRITICAL, "Cryptocurrency miner"),
    "stratum": (Severity.CRITICAL, "Mining pool connection"),
    "nc -e": (Severity.CRITICAL, "Reverse shell (netcat)"),
    "ncat -e": (Severity.CRITICAL, "Reverse shell (ncat)"),
    "bash -i": (Severity.CRITICAL, "Interactive bash (potential reverse shell)"),
    "/dev/tcp/": (Severity.CRITICAL, "Bash reverse shell"),
    "socat": (Severity.HIGH, "Network relay tool"),
    "chisel": (Severity.HIGH, "Tunneling tool"),
    "ngrok": (Severity.HIGH, "Reverse proxy/tunnel"),
}

# Sensitive filesystem locations
SENSITIVE_PATHS = {
    "/etc/shadow": (Severity.CRITICAL, "Password file modified"),
    "/etc/passwd": (Severity.HIGH, "User database modified"),
    "/root/.ssh": (Severity.CRITICAL, "SSH keys modified"),
    "/etc/crontab": (Severity.HIGH, "Cron jobs modified (persistence)"),
    "/var/spool/cron": (Severity.HIGH, "Cron jobs modified"),
    "/etc/sudoers": (Severity.CRITICAL, "Sudo configuration modified"),
    "/etc/ld.so.preload": (Severity.CRITICAL, "Library preloading (rootkit indicator)"),
}


class RuntimeBehaviorAgent(BaseAgent):
    """Monitor container runtime behavior for anomalies during sandbox execution."""

    name: ClassVar[str] = "runtime_behavior"
    description: ClassVar[str] = (
        "Monitors container behavior during sandbox execution including "
        "running processes, filesystem changes, network connections, "
        "and resource usage to detect anomalous or malicious activity."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM06", "LLM10", "ASI02", "ASI05", "ASI10"]
    depends_on: ClassVar[list[str]] = ["network", "permission"]

    async def analyze(self) -> None:
        """Run runtime behavior monitoring checks."""
        cid = self.context.container_id
        if not cid:
            self.add_finding(
                title="No container available for runtime monitoring",
                description=(
                    "Runtime behavior analysis requires a running container. "
                    "No container ID was found in the scan context."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
            )
            return

        await self._check_processes(cid)
        await self._check_filesystem_changes(cid)
        await self._check_network_connections(cid)
        await self._check_resource_usage(cid)
        await self._check_root_processes(cid)

    async def _check_processes(self, cid: str) -> None:
        """Check running processes for suspicious activity."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "ps", "aux",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            ps_output = stdout.decode(errors="replace")
        except Exception:
            return

        suspicious_found: list[tuple[str, Severity, str, str]] = []

        for line in ps_output.splitlines()[1:]:  # Skip header
            line_lower = line.lower()
            for pattern, (severity, label) in SUSPICIOUS_PROCESSES.items():
                if pattern.lower() in line_lower:
                    suspicious_found.append((pattern, severity, label, line.strip()))

        if suspicious_found:
            details = "\n".join(
                f"  [{label}] {ps_line[:120]}"
                for _, _, label, ps_line in suspicious_found
            )
            worst_sev = min(
                (sev for _, sev, _, _ in suspicious_found),
                key=lambda s: list(Severity).index(s),
            )
            self.add_finding(
                title=f"Suspicious processes detected ({len(suspicious_found)})",
                description=(
                    f"Found {len(suspicious_found)} suspicious process(es) running "
                    "in the container. These may indicate compromise, cryptocurrency "
                    "mining, reverse shells, or unauthorized network tunneling."
                ),
                severity=worst_sev,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI05", "ASI10"],
                nist_ai_rmf=["MANAGE"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary=f"{len(suspicious_found)} suspicious processes",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Investigate the suspicious processes immediately. Check for "
                    "compromise indicators. Use seccomp profiles and AppArmor to "
                    "restrict process execution."
                ),
                cvss_score=9.0 if worst_sev == Severity.CRITICAL else 7.0,
                ai_risk_score=9.0,
            )

        # Count total processes
        process_count = len(ps_output.splitlines()) - 1
        if process_count > 50:
            self.add_finding(
                title=f"Unusually high process count ({process_count})",
                description=(
                    f"The container has {process_count} running processes, "
                    "which is unusually high for an AI agent container. This "
                    "could indicate a process spawning vulnerability or "
                    "resource abuse."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM10"],
                owasp_agentic=["ASI05"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary=f"{process_count} processes",
                        raw_data=ps_output[:500],
                        location=f"container:{cid}",
                    )
                ],
                remediation="Investigate and limit process spawning. Use PID limits.",
            )

    async def _check_filesystem_changes(self, cid: str) -> None:
        """Check for filesystem modifications during execution."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "diff", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            diff_output = stdout.decode(errors="replace")
        except Exception:
            return

        if not diff_output.strip():
            return

        changes = diff_output.strip().splitlines()
        sensitive_changes: list[tuple[str, str, Severity, str]] = []
        tmp_writes: list[str] = []

        for line in changes:
            # Format: C|A|D /path
            if len(line) < 3:
                continue
            change_type = line[0]  # C=changed, A=added, D=deleted
            path = line[2:].strip()

            for sensitive_path, (severity, label) in SENSITIVE_PATHS.items():
                if path.startswith(sensitive_path):
                    sensitive_changes.append((path, change_type, severity, label))

            if path.startswith("/tmp/") and change_type == "A":
                tmp_writes.append(path)

        if sensitive_changes:
            details = "\n".join(
                f"  [{change_type}] {path} -- {label}"
                for path, change_type, _, label in sensitive_changes
            )
            worst_sev = min(
                (sev for _, _, sev, _ in sensitive_changes),
                key=lambda s: list(Severity).index(s),
            )
            self.add_finding(
                title=f"Sensitive filesystem locations modified ({len(sensitive_changes)})",
                description=(
                    f"Found {len(sensitive_changes)} modification(s) to sensitive "
                    "filesystem locations during container execution. This may "
                    "indicate privilege escalation, persistence mechanisms, or "
                    "credential theft attempts."
                ),
                severity=worst_sev,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI05", "ASI10"],
                nist_ai_rmf=["MANAGE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Sensitive FS modifications",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Use read-only root filesystem (--read-only). Mount only "
                    "necessary paths as writable. Investigate all modifications "
                    "to sensitive locations."
                ),
                cvss_score=9.0 if worst_sev == Severity.CRITICAL else 7.0,
                ai_risk_score=9.0,
            )

        # Report total change count
        if len(changes) > 100:
            self.add_finding(
                title=f"Excessive filesystem modifications ({len(changes)} changes)",
                description=(
                    f"The container made {len(changes)} filesystem changes during "
                    "execution. High filesystem activity may indicate data "
                    "exfiltration staging, malware unpacking, or unauthorized "
                    "file creation."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI05"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(changes)} FS changes",
                        raw_data="\n".join(changes[:30]),
                        location=f"container:{cid}",
                    )
                ],
                remediation="Use --read-only filesystem and limit writable mount points.",
            )

    async def _check_network_connections(self, cid: str) -> None:
        """Check established network connections for suspicious activity."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || cat /proc/net/tcp 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            net_output = stdout.decode(errors="replace")
        except Exception:
            return

        if not net_output.strip():
            return

        # Parse established connections
        established = []
        for line in net_output.splitlines():
            if "ESTAB" in line or "ESTABLISHED" in line:
                established.append(line.strip())

        # Check for connections to external IPs
        external_connections: list[str] = []
        internal_prefixes = ("127.", "10.", "172.16.", "172.17.", "192.168.", "0.0.0.0", "::")
        for conn in established:
            parts = conn.split()
            for part in parts:
                # Look for IP:port patterns
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", part)
                if ip_match:
                    ip = ip_match.group(1)
                    if not any(ip.startswith(prefix) for prefix in internal_prefixes):
                        external_connections.append(conn)
                        break

        if external_connections:
            self.add_finding(
                title=f"External network connections detected ({len(external_connections)})",
                description=(
                    f"Found {len(external_connections)} established connection(s) "
                    "to external IP addresses. These could indicate data "
                    "exfiltration, command & control communication, or "
                    "unauthorized API calls."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06", "LLM10"],
                owasp_agentic=["ASI02", "ASI10"],
                nist_ai_rmf=["MANAGE"],
                evidence=[
                    Evidence(
                        type="network_capture",
                        summary=f"{len(external_connections)} external connections",
                        raw_data="\n".join(external_connections[:20]),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Restrict outbound network access using network policies or "
                    "iptables rules. Only allow connections to known, required "
                    "endpoints. Monitor and log all outbound connections."
                ),
                cvss_score=7.0,
                ai_risk_score=8.0,
            )

        # Report listening ports
        listening = [
            line.strip() for line in net_output.splitlines()
            if "LISTEN" in line
        ]
        if len(listening) > 5:
            self.add_finding(
                title=f"Multiple listening ports ({len(listening)})",
                description=(
                    f"The container has {len(listening)} listening ports, which "
                    "increases the attack surface."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI03"],
                evidence=[
                    Evidence(
                        type="network_capture",
                        summary=f"{len(listening)} listening ports",
                        raw_data="\n".join(listening[:15]),
                        location=f"container:{cid}",
                    )
                ],
                remediation="Minimize listening ports to only those required.",
            )

    async def _check_resource_usage(self, cid: str) -> None:
        """Check container resource usage for anomalies."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "stats", cid,
                "--no-stream", "--format",
                '{"cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}","mem_perc":"{{.MemPerc}}","net":"{{.NetIO}}","pids":"{{.PIDs}}"}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            stats_raw = stdout.decode(errors="replace").strip()
        except Exception:
            return

        if not stats_raw:
            return

        try:
            stats = json.loads(stats_raw)
        except json.JSONDecodeError:
            return

        # Check CPU usage
        cpu_str = stats.get("cpu", "0%").replace("%", "")
        try:
            cpu_percent = float(cpu_str)
        except ValueError:
            cpu_percent = 0.0

        if cpu_percent > 90:
            self.add_finding(
                title=f"Excessive CPU usage ({cpu_percent:.1f}%)",
                description=(
                    f"Container CPU usage is {cpu_percent:.1f}%, which may "
                    "indicate cryptocurrency mining, denial of service, or "
                    "resource exhaustion attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM10"],
                owasp_agentic=["ASI05"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary=f"CPU: {cpu_percent:.1f}%",
                        raw_data=json.dumps(stats, indent=2),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Set CPU limits using --cpus flag. Investigate the cause "
                    "of high CPU usage. Check for mining processes."
                ),
                cvss_score=6.0,
            )

        # Check memory usage percentage
        mem_str = stats.get("mem_perc", "0%").replace("%", "")
        try:
            mem_percent = float(mem_str)
        except ValueError:
            mem_percent = 0.0

        if mem_percent > 90:
            self.add_finding(
                title=f"Excessive memory usage ({mem_percent:.1f}%)",
                description=(
                    f"Container memory usage is {mem_percent:.1f}%, "
                    "approaching the limit. This may indicate memory leaks, "
                    "DoS conditions, or resource exhaustion."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM10"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary=f"Memory: {mem_percent:.1f}%",
                        raw_data=json.dumps(stats, indent=2),
                        location=f"container:{cid}",
                    )
                ],
                remediation="Set memory limits using --memory flag.",
            )

    async def _check_root_processes(self, cid: str) -> None:
        """Check for processes running as root."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "ps -eo user,pid,cmd 2>/dev/null | grep -E '^root' | head -30",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            root_procs = stdout.decode(errors="replace").strip()
        except Exception:
            return

        if not root_procs:
            return

        root_lines = root_procs.strip().splitlines()
        # Filter out expected root processes
        unexpected_root: list[str] = []
        expected_names = {"init", "sh", "bash", "sleep", "tini", "dumb-init", "s6"}
        for line in root_lines:
            parts = line.split()
            if len(parts) >= 3:
                cmd_name = parts[2].split("/")[-1]
                if cmd_name not in expected_names:
                    unexpected_root.append(line.strip())

        if len(unexpected_root) > 3:
            self.add_finding(
                title=f"Multiple processes running as root ({len(unexpected_root)})",
                description=(
                    f"Found {len(unexpected_root)} non-init processes running "
                    "as root. Following least privilege principle, application "
                    "processes should run as non-root users."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary=f"{len(unexpected_root)} root processes",
                        raw_data="\n".join(unexpected_root[:15]),
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Run application processes as a non-root user. Set USER "
                    "in Dockerfile and use --user flag in docker run."
                ),
                cvss_score=5.0,
            )
