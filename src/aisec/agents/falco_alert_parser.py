"""Parser for Falco JSON alert output, mapping alerts to AiSec findings."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from aisec.core.enums import Severity
from aisec.core.models import Evidence, Finding

logger = logging.getLogger(__name__)


@dataclass
class FalcoAlert:
    """Parsed Falco alert."""

    rule: str = ""
    priority: str = ""
    output: str = ""
    output_fields: dict[str, Any] = field(default_factory=dict)
    time: str = ""
    tags: list[str] = field(default_factory=list)


# Maps Falco rule names to (Severity, owasp_llm, owasp_agentic, nist_ai_rmf)
RULE_SEVERITY_MAP: dict[str, tuple[Severity, list[str], list[str], list[str]]] = {
    "AI Model File Tampering": (
        Severity.CRITICAL,
        ["LLM06"],
        ["ASI02", "ASI10"],
        ["GOVERN-1", "MAP-3"],
    ),
    "Suspicious GPU Access": (
        Severity.MEDIUM,
        ["LLM10"],
        ["ASI05"],
        ["GOVERN-1"],
    ),
    "Prompt Injection via Environment": (
        Severity.HIGH,
        ["LLM01"],
        ["ASI01", "ASI04"],
        ["GOVERN-1", "MAP-2"],
    ),
    "Cryptocurrency Mining Activity": (
        Severity.CRITICAL,
        ["LLM06"],
        ["ASI10"],
        ["GOVERN-1"],
    ),
    "Data Exfiltration via DNS": (
        Severity.HIGH,
        ["LLM06"],
        ["ASI02", "ASI05"],
        ["GOVERN-1", "MAP-3"],
    ),
    "Unauthorized Model Download": (
        Severity.HIGH,
        ["LLM05"],
        ["ASI03", "ASI06"],
        ["MAP-3", "MANAGE-2"],
    ),
    "Container Escape Attempt": (
        Severity.CRITICAL,
        ["LLM06"],
        ["ASI10"],
        ["GOVERN-1"],
    ),
    "Reverse Shell Spawned": (
        Severity.CRITICAL,
        ["LLM06"],
        ["ASI10"],
        ["GOVERN-1"],
    ),
    "Training Data Access": (
        Severity.LOW,
        ["LLM06"],
        ["ASI02"],
        ["MAP-3"],
    ),
}

_PRIORITY_TO_SEVERITY: dict[str, Severity] = {
    "EMERGENCY": Severity.CRITICAL,
    "ALERT": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "NOTICE": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
    "DEBUG": Severity.INFO,
}


class FalcoAlertParser:
    """Parse Falco JSON output and convert alerts to AiSec findings."""

    def parse_json_line(self, line: str) -> FalcoAlert | None:
        """Parse a single line of Falco JSON output."""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON Falco output: %s", line[:120])
            return None

        return FalcoAlert(
            rule=data.get("rule", ""),
            priority=data.get("priority", ""),
            output=data.get("output", ""),
            output_fields=data.get("output_fields", {}),
            time=data.get("time", ""),
            tags=data.get("tags", []),
        )

    def parse_output(self, text: str) -> list[FalcoAlert]:
        """Parse the full Falco output (one JSON object per line)."""
        alerts: list[FalcoAlert] = []
        for line in text.splitlines():
            alert = self.parse_json_line(line)
            if alert and alert.rule:
                alerts.append(alert)
        return alerts

    def to_finding(self, alert: FalcoAlert) -> Finding:
        """Convert a Falco alert to an AiSec Finding."""
        rule_info = RULE_SEVERITY_MAP.get(alert.rule)
        if rule_info:
            severity, owasp_llm, owasp_agentic, nist_ai_rmf = rule_info
        else:
            severity = _PRIORITY_TO_SEVERITY.get(alert.priority.upper(), Severity.MEDIUM)
            owasp_llm = ["LLM06"]
            owasp_agentic = ["ASI10"]
            nist_ai_rmf = ["GOVERN-1"]

        evidence = []
        if alert.output:
            evidence.append(Evidence(
                type="falco_runtime",
                summary=alert.rule,
                raw_data=alert.output,
                location=alert.output_fields.get("fd.name", ""),
            ))

        container_id = alert.output_fields.get("container.id", "")
        process_name = alert.output_fields.get("proc.name", "")

        return Finding(
            title=f"Falco: {alert.rule}",
            description=(
                f"Falco runtime detection: {alert.output}. "
                f"Process: {process_name}, Container: {container_id}"
            ),
            severity=severity,
            agent="falco_runtime",
            owasp_llm=owasp_llm,
            owasp_agentic=owasp_agentic,
            nist_ai_rmf=nist_ai_rmf,
            evidence=evidence,
            remediation=_get_remediation(alert.rule),
            cvss_score=_severity_to_cvss(severity),
            ai_risk_score=_severity_to_ai_risk(severity),
        )


def _get_remediation(rule: str) -> str:
    """Return remediation guidance for a Falco rule."""
    remediations = {
        "AI Model File Tampering": (
            "Ensure model files are read-only in production. Use file integrity monitoring "
            "and cryptographic checksums to detect tampering."
        ),
        "Suspicious GPU Access": (
            "Restrict GPU device access to authorised processes only. Use device cgroups "
            "or container security policies."
        ),
        "Prompt Injection via Environment": (
            "Avoid storing sensitive prompts or API keys in environment variables. "
            "Use a secrets manager with runtime injection."
        ),
        "Cryptocurrency Mining Activity": (
            "Terminate the mining process immediately. Investigate the attack vector "
            "and scan for additional compromise indicators."
        ),
        "Data Exfiltration via DNS": (
            "Block DNS tunnelling with DNS monitoring and response policy zones (RPZ). "
            "Restrict outbound DNS to trusted resolvers."
        ),
        "Unauthorized Model Download": (
            "Restrict outbound network access to approved model registries. "
            "Use a model proxy or firewall rules."
        ),
        "Container Escape Attempt": (
            "Run containers with minimal privileges. Disable privileged mode, "
            "drop all capabilities, and use seccomp/AppArmor profiles."
        ),
        "Reverse Shell Spawned": (
            "Terminate the reverse shell immediately. Investigate ingress vector "
            "and rotate all credentials."
        ),
        "Training Data Access": (
            "Restrict training data access to authorised processes. Use RBAC and "
            "audit logging for data access."
        ),
    }
    return remediations.get(rule, "Investigate the alert and apply appropriate security controls.")


def _severity_to_cvss(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.5,
        Severity.INFO: 1.0,
    }.get(severity, 5.0)


def _severity_to_ai_risk(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
    }.get(severity, 5.0)
