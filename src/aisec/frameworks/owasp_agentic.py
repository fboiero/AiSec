"""OWASP Top 10 for Agentic Applications (2026) definitions and mapping utilities.

This module provides the complete OWASP Top 10 for Agentic Applications
taxonomy along with functions to look up categories and map security findings
to their corresponding OWASP Agentic categories.

Reference: https://owasp.org/www-project-agentic-ai-threats/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aisec.core.enums import OwaspAgenticCategory, Severity
from aisec.core.models import Finding


@dataclass
class OwaspAgenticItem:
    """A single OWASP Agentic Applications Top 10 category item."""

    id: str
    name: str
    description: str
    risk_level: Severity
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OWASP Top 10 for Agentic Applications (2026) Registry
# ---------------------------------------------------------------------------

OWASP_AGENTIC_TOP_10: dict[str, OwaspAgenticItem] = {
    "ASI01": OwaspAgenticItem(
        id="ASI01",
        name="Agent Goal Hijacking",
        description=(
            "Attackers manipulate an AI agent's objectives through prompt "
            "injection, adversarial inputs, or environmental manipulation, "
            "causing the agent to pursue goals different from those intended "
            "by its designers. This is especially dangerous in autonomous "
            "agents that chain multiple actions without human oversight."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI02": OwaspAgenticItem(
        id="ASI02",
        name="Tool Misuse",
        description=(
            "An AI agent invokes external tools, APIs, or services in "
            "unintended or harmful ways. This may result from crafted inputs "
            "that trick the agent into calling the wrong tool, passing "
            "malicious parameters, or chaining tool invocations in a "
            "dangerous sequence that bypasses safety controls."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI03": OwaspAgenticItem(
        id="ASI03",
        name="Identity and Privilege Abuse",
        description=(
            "An AI agent operates with overly broad credentials or assumes "
            "identities beyond its intended scope. Attackers exploit the "
            "agent's access to perform privilege escalation, impersonate "
            "users, or access protected resources that should be restricted "
            "to specific roles or contexts."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI04": OwaspAgenticItem(
        id="ASI04",
        name="Supply Chain Vulnerabilities",
        description=(
            "Compromised or malicious components in the agent's supply chain, "
            "including third-party tools, plugins, models, data sources, and "
            "orchestration frameworks. Attackers tamper with upstream "
            "dependencies to inject backdoors or exfiltrate data through "
            "the agent's trusted integrations."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI05": OwaspAgenticItem(
        id="ASI05",
        name="Unexpected Code Execution",
        description=(
            "An AI agent generates and executes code in an unsandboxed "
            "environment, leading to arbitrary command execution, file system "
            "access, or network operations. This includes code injection "
            "through crafted prompts that trick the agent into running "
            "malicious scripts or shell commands."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI06": OwaspAgenticItem(
        id="ASI06",
        name="Memory and Context Poisoning",
        description=(
            "Attackers corrupt the agent's persistent memory, conversation "
            "history, or retrieval context to influence future decisions. "
            "Poisoned memories propagate across sessions, causing the agent "
            "to rely on tainted data for reasoning, planning, and action "
            "selection in subsequent interactions."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI07": OwaspAgenticItem(
        id="ASI07",
        name="Insecure Inter-Agent Communication",
        description=(
            "Messages exchanged between agents in a multi-agent system lack "
            "authentication, integrity verification, or confidentiality "
            "protections. Attackers intercept, modify, or inject messages "
            "to manipulate collaboration workflows, spread misinformation "
            "between agents, or escalate privileges."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI08": OwaspAgenticItem(
        id="ASI08",
        name="Cascading Failures",
        description=(
            "A failure or compromise in one agent propagates through a "
            "multi-agent system, causing widespread disruption. Tightly "
            "coupled agents amplify errors, create feedback loops, or "
            "trigger chain reactions that degrade system integrity, "
            "availability, or safety beyond the initial point of failure."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI09": OwaspAgenticItem(
        id="ASI09",
        name="Human-Agent Trust Exploitation",
        description=(
            "An AI agent exploits or manipulates the trust relationship with "
            "human users. This includes social engineering through convincing "
            "but deceptive outputs, creating false urgency to bypass human "
            "review, or gradually expanding its operational scope beyond "
            "what was explicitly authorised."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
    "ASI10": OwaspAgenticItem(
        id="ASI10",
        name="Rogue Agents",
        description=(
            "An AI agent deviates from its intended behaviour and operates "
            "outside defined boundaries. This may result from adversarial "
            "attacks, emergent behaviour in complex multi-agent systems, or "
            "misaligned reward functions that incentivise the agent to take "
            "actions contrary to operator intent."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://owasp.org/www-project-agentic-ai-threats/",
        ],
    ),
}


def get_category(category_id: str) -> OwaspAgenticItem | None:
    """Look up an OWASP Agentic Applications Top 10 category by identifier.

    Args:
        category_id: The category identifier (e.g. ``"ASI01"``).  The lookup
            is case-insensitive and tolerates leading/trailing whitespace.

    Returns:
        The corresponding :class:`OwaspAgenticItem`, or ``None`` if the
        identifier is not recognised.
    """
    return OWASP_AGENTIC_TOP_10.get(category_id.strip().upper())


def map_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group a list of findings by their OWASP Agentic Applications category.

    Each :class:`~aisec.core.models.Finding` may reference zero or more
    OWASP Agentic categories via its ``owasp_agentic`` field.  This function
    builds a mapping from each referenced category identifier to the
    findings associated with it.

    Args:
        findings: Security findings to categorise.

    Returns:
        A dictionary whose keys are OWASP Agentic category identifiers
        (e.g. ``"ASI01"``) and whose values are the lists of findings
        mapped to that category.  Categories with no associated findings
        are omitted from the result.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        for category_id in finding.owasp_agentic:
            normalised = category_id.strip().upper()
            if normalised in OWASP_AGENTIC_TOP_10:
                grouped.setdefault(normalised, []).append(finding)
    return grouped
