"""NIST AI Risk Management Framework (AI RMF 1.0) mapping for AI agent security.

This module defines the four core NIST AI RMF functions -- GOVERN, MAP,
MEASURE, and MANAGE -- along with key subcategories relevant to securing
AI agent systems.  It provides lookup and mapping utilities for associating
security findings with the framework.

Reference: https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aisec.core.enums import NistAiRmfFunction, Severity
from aisec.core.models import Finding


@dataclass
class NistSubcategory:
    """A subcategory within a NIST AI RMF function."""

    id: str
    name: str
    description: str
    guidance: str = ""


@dataclass
class NistFunction:
    """One of the four core NIST AI RMF functions."""

    id: str
    name: str
    description: str
    subcategories: list[NistSubcategory] = field(default_factory=list)


# ---------------------------------------------------------------------------
# GOVERN - Policies, accountability, and risk culture
# ---------------------------------------------------------------------------

GOVERN = NistFunction(
    id="GOVERN",
    name="Govern",
    description=(
        "Cultivate and implement a culture of AI risk management across the "
        "organisation.  Establish policies, define roles and accountability, "
        "and foster a risk-aware culture that spans the AI system lifecycle."
    ),
    subcategories=[
        NistSubcategory(
            id="GV-1",
            name="AI Risk Management Policies",
            description=(
                "Policies and procedures for AI risk management are established "
                "and integrated into the organisation's overall risk governance."
            ),
            guidance=(
                "Define organisational policies that explicitly address AI agent "
                "security, including acceptable use, deployment approval "
                "workflows, and incident escalation procedures."
            ),
        ),
        NistSubcategory(
            id="GV-2",
            name="Accountability Structures",
            description=(
                "Roles, responsibilities, and lines of accountability for AI "
                "risk management are clearly defined and documented."
            ),
            guidance=(
                "Assign ownership for AI agent security across development, "
                "deployment, and operations teams.  Ensure clear escalation "
                "paths for agent-related security incidents."
            ),
        ),
        NistSubcategory(
            id="GV-3",
            name="Risk Culture and Awareness",
            description=(
                "The organisation fosters a culture that is aware of AI risks "
                "and encourages responsible AI practices at every level."
            ),
            guidance=(
                "Provide training on AI agent threat models, prompt injection "
                "risks, and responsible AI practices.  Encourage reporting of "
                "anomalous agent behaviour."
            ),
        ),
        NistSubcategory(
            id="GV-4",
            name="Workforce Diversity and Expertise",
            description=(
                "The organisation maintains diverse and skilled teams capable "
                "of identifying and managing AI-specific risks."
            ),
            guidance=(
                "Ensure security teams include expertise in LLM security, "
                "agentic architectures, and adversarial machine learning."
            ),
        ),
        NistSubcategory(
            id="GV-5",
            name="Third-Party Risk Management",
            description=(
                "Policies govern the assessment and monitoring of risks "
                "introduced by third-party AI components and services."
            ),
            guidance=(
                "Evaluate third-party model providers, tool integrations, and "
                "plugin ecosystems for security posture and data handling "
                "practices before integration with agent systems."
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# MAP - Context, risk identification, and stakeholders
# ---------------------------------------------------------------------------

MAP = NistFunction(
    id="MAP",
    name="Map",
    description=(
        "Establish the context for AI risk management.  Identify and document "
        "the risks associated with the AI system, its stakeholders, and the "
        "intended deployment environment."
    ),
    subcategories=[
        NistSubcategory(
            id="MP-1",
            name="System Context and Scope",
            description=(
                "The AI system's intended purpose, deployment context, and "
                "operational boundaries are defined and documented."
            ),
            guidance=(
                "Document the agent's intended capabilities, tool access, "
                "data sources, and the environments in which it will operate. "
                "Define explicit boundaries for autonomous actions."
            ),
        ),
        NistSubcategory(
            id="MP-2",
            name="Risk Identification",
            description=(
                "AI-specific risks are systematically identified, including "
                "adversarial, reliability, and societal risks."
            ),
            guidance=(
                "Conduct threat modelling for agentic workflows, including "
                "prompt injection vectors, tool-call chains, and "
                "inter-agent communication channels."
            ),
        ),
        NistSubcategory(
            id="MP-3",
            name="Stakeholder Engagement",
            description=(
                "Relevant stakeholders -- including end users, affected "
                "communities, and domain experts -- are identified and engaged."
            ),
            guidance=(
                "Involve security, legal, compliance, and end-user "
                "representatives when assessing AI agent deployments.  "
                "Document stakeholder concerns regarding agent autonomy."
            ),
        ),
        NistSubcategory(
            id="MP-4",
            name="Impact Assessment",
            description=(
                "The potential impacts of the AI system on individuals, "
                "groups, organisations, and society are evaluated."
            ),
            guidance=(
                "Assess the blast radius of agent compromise scenarios, "
                "including data exfiltration, privilege escalation, and "
                "cascading failures across multi-agent systems."
            ),
        ),
        NistSubcategory(
            id="MP-5",
            name="Data and Model Cataloguing",
            description=(
                "Data sources, model provenance, and dependencies are "
                "catalogued and tracked throughout the AI lifecycle."
            ),
            guidance=(
                "Maintain an inventory of all models, embeddings, vector "
                "stores, and external data sources consumed by agents.  "
                "Track provenance and integrity of each component."
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# MEASURE - Assessment metrics, testing, and monitoring
# ---------------------------------------------------------------------------

MEASURE = NistFunction(
    id="MEASURE",
    name="Measure",
    description=(
        "Employ quantitative and qualitative methods to analyse, assess, "
        "benchmark, and monitor AI risks and their associated impacts."
    ),
    subcategories=[
        NistSubcategory(
            id="MS-1",
            name="Risk Assessment Metrics",
            description=(
                "Quantitative and qualitative metrics for AI risk are defined "
                "and consistently applied across the system lifecycle."
            ),
            guidance=(
                "Define measurable security metrics for AI agents: prompt "
                "injection success rates, data leakage detection rates, "
                "tool misuse frequency, and mean-time-to-detect anomalies."
            ),
        ),
        NistSubcategory(
            id="MS-2",
            name="Security Testing",
            description=(
                "AI systems undergo systematic security testing, including "
                "adversarial testing and red-teaming exercises."
            ),
            guidance=(
                "Perform automated and manual security testing of agent "
                "systems, including prompt injection fuzzing, tool-call "
                "boundary testing, and multi-agent adversarial simulations."
            ),
        ),
        NistSubcategory(
            id="MS-3",
            name="Continuous Monitoring",
            description=(
                "AI systems are continuously monitored for drift, degradation, "
                "and emerging risks throughout their operational life."
            ),
            guidance=(
                "Monitor agent behaviour in production for anomalous tool "
                "calls, unexpected data access patterns, and deviations "
                "from baseline behaviour profiles."
            ),
        ),
        NistSubcategory(
            id="MS-4",
            name="Bias and Fairness Evaluation",
            description=(
                "The AI system is evaluated for unintended bias and fairness "
                "concerns relevant to its deployment context."
            ),
            guidance=(
                "Assess whether agent outputs or decisions exhibit "
                "discriminatory patterns, particularly when agents interact "
                "with diverse user populations or handle sensitive data."
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# MANAGE - Risk response, incident management, continuous improvement
# ---------------------------------------------------------------------------

MANAGE = NistFunction(
    id="MANAGE",
    name="Manage",
    description=(
        "Allocate resources and implement plans to respond to, recover from, "
        "and communicate about AI risks and incidents."
    ),
    subcategories=[
        NistSubcategory(
            id="MG-1",
            name="Risk Response and Prioritisation",
            description=(
                "Identified AI risks are prioritised and addressed through "
                "mitigation, transfer, acceptance, or avoidance strategies."
            ),
            guidance=(
                "Prioritise agent security findings by severity and blast "
                "radius.  Implement mitigations such as tool-call allowlists, "
                "output sanitisation, and human-in-the-loop gates."
            ),
        ),
        NistSubcategory(
            id="MG-2",
            name="Incident Management",
            description=(
                "Processes are established for detecting, reporting, and "
                "responding to AI-related security incidents."
            ),
            guidance=(
                "Define incident response playbooks specific to agent "
                "compromise scenarios: prompt injection exploitation, "
                "data exfiltration via agents, and rogue agent containment."
            ),
        ),
        NistSubcategory(
            id="MG-3",
            name="Continuous Improvement",
            description=(
                "Lessons learned from incidents, monitoring, and testing are "
                "fed back into the AI risk management process."
            ),
            guidance=(
                "Conduct post-incident reviews for agent security events. "
                "Update threat models, detection rules, and agent guardrails "
                "based on new attack patterns and research."
            ),
        ),
        NistSubcategory(
            id="MG-4",
            name="Communication and Disclosure",
            description=(
                "AI risks and incidents are communicated transparently to "
                "relevant stakeholders, including affected users."
            ),
            guidance=(
                "Establish communication plans for AI agent security incidents "
                "that address disclosure obligations under GDPR, CCPA, and "
                "other applicable regulations."
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# Consolidated registry
# ---------------------------------------------------------------------------

NIST_AI_RMF_FUNCTIONS: dict[str, NistFunction] = {
    "GOVERN": GOVERN,
    "MAP": MAP,
    "MEASURE": MEASURE,
    "MANAGE": MANAGE,
}

# Build a flat lookup of all subcategories keyed by their ID.
_SUBCATEGORY_INDEX: dict[str, tuple[NistFunction, NistSubcategory]] = {}
for _func in NIST_AI_RMF_FUNCTIONS.values():
    for _sub in _func.subcategories:
        _SUBCATEGORY_INDEX[_sub.id] = (_func, _sub)


def get_function(function_id: str) -> NistFunction | None:
    """Look up a NIST AI RMF function by its identifier.

    Args:
        function_id: The function identifier (e.g. ``"GOVERN"``).  The lookup
            is case-insensitive and tolerates leading/trailing whitespace.

    Returns:
        The corresponding :class:`NistFunction`, or ``None`` if the
        identifier is not recognised.
    """
    return NIST_AI_RMF_FUNCTIONS.get(function_id.strip().upper())


def get_subcategory(subcategory_id: str) -> NistSubcategory | None:
    """Look up a NIST AI RMF subcategory by its identifier.

    Args:
        subcategory_id: The subcategory identifier (e.g. ``"GV-1"``).

    Returns:
        The corresponding :class:`NistSubcategory`, or ``None`` if the
        identifier is not recognised.
    """
    entry = _SUBCATEGORY_INDEX.get(subcategory_id.strip().upper())
    return entry[1] if entry else None


def map_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group a list of findings by their NIST AI RMF subcategory.

    Each :class:`~aisec.core.models.Finding` may reference zero or more
    NIST AI RMF subcategories via its ``nist_ai_rmf`` field.  This function
    builds a mapping from each referenced subcategory identifier to the
    findings associated with it.

    Args:
        findings: Security findings to categorise.

    Returns:
        A dictionary whose keys are NIST AI RMF subcategory identifiers
        (e.g. ``"GV-1"``) and whose values are the lists of findings
        mapped to that subcategory.  Subcategories with no associated
        findings are omitted from the result.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        for subcategory_id in finding.nist_ai_rmf:
            normalised = subcategory_id.strip().upper()
            if normalised in _SUBCATEGORY_INDEX:
                grouped.setdefault(normalised, []).append(finding)
    return grouped
