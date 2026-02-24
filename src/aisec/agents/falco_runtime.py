"""Falco runtime monitoring agent — deploys Falco sidecar for eBPF syscall analysis."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Path to custom Falco rules bundled with AiSec
_RULES_PATH = Path(__file__).parent / "falco_rules.yaml"

# Default monitoring duration in seconds
_DEFAULT_MONITOR_SECONDS = 30


class FalcoRuntimeAgent(BaseAgent):
    """Deploy Falco as a sidecar container for real-time syscall monitoring.

    Detects AI-specific runtime threats: model tampering, crypto mining,
    data exfiltration, container escape, and prompt injection via environment.
    Requires Docker and the falcosecurity/falco-no-driver image.
    """

    name: ClassVar[str] = "falco_runtime"
    description: ClassVar[str] = (
        "Deploys a Falco sidecar container sharing the PID namespace with the "
        "target to monitor syscalls in real time. Uses custom AI/ML-specific "
        "rules to detect model tampering, crypto mining, data exfiltration, "
        "container escape attempts, and prompt injection via environment variables."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = [
        "LLM01", "LLM05", "LLM06", "LLM10",
        "ASI01", "ASI02", "ASI03", "ASI05", "ASI10",
    ]
    depends_on: ClassVar[list[str]] = ["runtime_behavior"]

    async def analyze(self) -> None:
        """Run Falco runtime monitoring analysis."""
        # Check if Falco is enabled in config
        falco_enabled = getattr(self.context.config, "falco_enabled", False)
        if not falco_enabled:
            logger.info("Falco runtime monitoring disabled in config")
            return

        cid = self.context.container_id
        if not cid:
            logger.info("No container running — skipping Falco runtime monitoring")
            return

        dm = self.context.docker_manager
        if dm is None:
            logger.info("No Docker manager — skipping Falco runtime monitoring")
            return

        # Deploy Falco sidecar
        falco_container = await self._deploy_falco(dm, cid)
        if falco_container is None:
            return

        # Let Falco monitor for a period
        monitor_seconds = _DEFAULT_MONITOR_SECONDS
        logger.info("Monitoring with Falco for %d seconds...", monitor_seconds)
        await asyncio.sleep(monitor_seconds)

        # Collect and parse alerts
        alerts_text = self._collect_alerts(falco_container)
        self._parse_alerts(alerts_text)

        # Also run static checks on container state
        await self._check_container_state(dm)

    async def _deploy_falco(self, dm: Any, target_cid: str) -> Any:
        """Deploy Falco sidecar with PID namespace sharing."""
        falco_image = getattr(self.context.config, "falco_image",
                              "falcosecurity/falco-no-driver:latest")

        # Prepare volumes — mount custom rules
        volumes: dict[str, dict[str, str]] = {}
        if _RULES_PATH.exists():
            volumes[str(_RULES_PATH)] = {
                "bind": "/etc/falco/falco_rules.local.yaml",
                "mode": "ro",
            }

        try:
            container = dm.deploy_sidecar(
                image=falco_image,
                name="falco",
                pid_mode=f"container:{target_cid}",
                volumes=volumes,
                privileged=True,
                environment={
                    "FALCO_BPF_PROBE": "",
                },
            )
            logger.info("Falco sidecar deployed: %s", container.short_id)
            return container
        except Exception as exc:
            logger.warning("Failed to deploy Falco sidecar: %s", exc)
            self.add_finding(
                title="Falco sidecar deployment failed",
                description=f"Could not deploy Falco runtime monitor: {exc}",
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI10"],
                remediation="Ensure Docker is running and the Falco image is accessible.",
            )
            return None

    def _collect_alerts(self, falco_container: Any) -> str:
        """Collect Falco alert output from the sidecar container."""
        try:
            falco_container.reload()
            logs = falco_container.logs(tail=500).decode("utf-8", errors="replace")
            return logs
        except Exception as exc:
            logger.warning("Failed to collect Falco logs: %s", exc)
            return ""

    def _parse_alerts(self, alerts_text: str) -> None:
        """Parse Falco JSON output and create findings."""
        if not alerts_text.strip():
            logger.info("No Falco alerts detected")
            return

        from aisec.agents.falco_alert_parser import FalcoAlertParser

        parser = FalcoAlertParser()
        alerts = parser.parse_output(alerts_text)

        if not alerts:
            logger.info("No actionable Falco alerts parsed")
            return

        logger.info("Parsed %d Falco alerts", len(alerts))

        # Deduplicate by rule name (keep first occurrence)
        seen_rules: set[str] = set()
        for alert in alerts:
            if alert.rule in seen_rules:
                continue
            seen_rules.add(alert.rule)

            finding = parser.to_finding(alert)
            self.add_finding(
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                owasp_llm=finding.owasp_llm,
                owasp_agentic=finding.owasp_agentic,
                nist_ai_rmf=finding.nist_ai_rmf,
                evidence=finding.evidence,
                remediation=finding.remediation,
                cvss_score=finding.cvss_score,
                ai_risk_score=finding.ai_risk_score,
            )

    async def _check_container_state(self, dm: Any) -> None:
        """Run additional static checks on the container while Falco monitors."""
        try:
            exit_code, output = dm.exec_in_target(
                "find /tmp /var/tmp -name '*.pt' -o -name '*.onnx' -o -name '*.safetensors' "
                "-o -name '*.pkl' 2>/dev/null || true"
            )
            if output.strip():
                self._check_model_files_in_tmp(output)
        except Exception:
            pass  # Container may not support exec

        try:
            exit_code, output = dm.exec_in_target(
                "ps aux 2>/dev/null || true"
            )
            if output.strip():
                self._check_suspicious_processes(output)
        except Exception:
            pass

    def _check_model_files_in_tmp(self, output: str) -> None:
        """Flag model files found in temporary directories."""
        files = [f.strip() for f in output.strip().splitlines() if f.strip()]
        if files:
            self.add_finding(
                title="Model files in temporary directories",
                description=(
                    f"Found {len(files)} model file(s) in /tmp or /var/tmp: "
                    f"{', '.join(files[:5])}. Model files in temporary directories "
                    "may indicate runtime model manipulation."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02"],
                evidence=[Evidence(type="falco_runtime", raw_data=output[:500])],
                remediation=(
                    "Store model files in read-only mounted volumes. "
                    "Investigate why models are being written to temporary directories."
                ),
            )

    def _check_suspicious_processes(self, ps_output: str) -> None:
        """Check process list for mining or reverse shell indicators."""
        suspicious = {
            "xmrig": (Severity.CRITICAL, "Cryptocurrency miner detected"),
            "minerd": (Severity.CRITICAL, "Cryptocurrency miner detected"),
            "cpuminer": (Severity.CRITICAL, "Cryptocurrency miner detected"),
            "nc -e": (Severity.CRITICAL, "Reverse shell via netcat"),
            "ncat -e": (Severity.CRITICAL, "Reverse shell via ncat"),
            "bash -i": (Severity.HIGH, "Interactive bash session"),
        }
        lower_output = ps_output.lower()
        for pattern, (severity, desc) in suspicious.items():
            if pattern in lower_output:
                self.add_finding(
                    title=f"Suspicious process: {desc}",
                    description=f"Runtime process monitoring detected: {desc}",
                    severity=severity,
                    owasp_llm=["LLM06"],
                    owasp_agentic=["ASI10"],
                    evidence=[Evidence(type="falco_runtime", raw_data=pattern)],
                    remediation="Terminate the suspicious process and investigate the attack vector.",
                )
