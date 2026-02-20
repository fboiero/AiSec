"""OWASP Top 10 for LLM Applications (2025) definitions and mapping utilities.

This module provides the complete OWASP LLM Top 10 (2025) taxonomy along with
functions to look up categories and map security findings to their corresponding
OWASP LLM categories.

Reference: https://genai.owasp.org/llm-top-10/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aisec.core.enums import OwaspLlmCategory, Severity
from aisec.core.models import Finding


@dataclass
class OwaspLlmItem:
    """A single OWASP LLM Top 10 category item."""

    id: str
    name: str
    description: str
    risk_level: Severity
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OWASP LLM Top 10 (2025) Registry
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10: dict[str, OwaspLlmItem] = {
    "LLM01": OwaspLlmItem(
        id="LLM01",
        name="Prompt Injection",
        description=(
            "Manipulating LLM behavior through crafted inputs. Attackers design "
            "prompts that override the model's instructions, bypass safety "
            "controls, or cause unintended actions. This includes both direct "
            "injection (user-supplied prompts) and indirect injection (external "
            "content consumed by the model)."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            "https://arxiv.org/abs/2302.12173",
        ],
    ),
    "LLM02": OwaspLlmItem(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description=(
            "Unauthorized exposure of private data through LLM responses. The "
            "model may reveal personally identifiable information, credentials, "
            "proprietary business data, or other confidential content present in "
            "its training data or context window."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
        ],
    ),
    "LLM03": OwaspLlmItem(
        id="LLM03",
        name="Supply Chain",
        description=(
            "Compromised components in the LLM supply chain. Vulnerabilities "
            "may arise from third-party datasets, pre-trained models, plugins, "
            "or extensions that introduce backdoors, biases, or security flaws "
            "into the application."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
        ],
    ),
    "LLM04": OwaspLlmItem(
        id="LLM04",
        name="Data and Model Poisoning",
        description=(
            "Manipulation of training data or models to compromise integrity. "
            "Attackers inject malicious data during training, fine-tuning, or "
            "embedding stages to introduce backdoors, biases, or degraded "
            "performance that can be exploited at inference time."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
        ],
    ),
    "LLM05": OwaspLlmItem(
        id="LLM05",
        name="Improper Output Handling",
        description=(
            "Inadequate validation of LLM outputs before downstream consumption. "
            "When LLM-generated content is passed to other systems without "
            "proper sanitisation, it can lead to cross-site scripting, SQL "
            "injection, command injection, or other injection attacks in "
            "backend components."
        ),
        risk_level=Severity.HIGH,
        references=[
            "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
        ],
    ),
    "LLM06": OwaspLlmItem(
        id="LLM06",
        name="Excessive Agency",
        description=(
            "Granting LLMs too much autonomy or access to external systems. "
            "When models are given unnecessary permissions, excessive "
            "functionality, or the ability to take high-impact actions without "
            "human oversight, compromised or misbehaving models can cause "
            "significant damage."
        ),
        risk_level=Severity.CRITICAL,
        references=[
            "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
        ],
    ),
    "LLM07": OwaspLlmItem(
        id="LLM07",
        name="System Prompt Leakage",
        description=(
            "Unauthorized extraction of system prompts and internal "
            "instructions. Attackers use adversarial techniques to make the "
            "model reveal its hidden configuration, system-level instructions, "
            "or security boundaries, enabling further targeted attacks."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
        ],
    ),
    "LLM08": OwaspLlmItem(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        description=(
            "Vulnerabilities in Retrieval-Augmented Generation (RAG) pipelines "
            "and vector databases. Attackers may manipulate embeddings, poison "
            "vector stores, or exploit retrieval mechanisms to inject malicious "
            "content into the model's context window."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
        ],
    ),
    "LLM09": OwaspLlmItem(
        id="LLM09",
        name="Misinformation",
        description=(
            "LLMs generating false or misleading content. Models may produce "
            "hallucinations, fabricated facts, or subtly incorrect information "
            "that appears authoritative, leading to flawed decision-making, "
            "reputational harm, or safety incidents."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://genai.owasp.org/llmrisk/llm09-misinformation/",
        ],
    ),
    "LLM10": OwaspLlmItem(
        id="LLM10",
        name="Unbounded Consumption",
        description=(
            "Uncontrolled resource usage by LLMs. Attackers or poorly designed "
            "integrations may trigger excessive API calls, unbounded token "
            "consumption, runaway inference loops, or denial-of-service "
            "conditions through resource-intensive queries."
        ),
        risk_level=Severity.MEDIUM,
        references=[
            "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
        ],
    ),
}


def get_category(category_id: str) -> OwaspLlmItem | None:
    """Look up an OWASP LLM Top 10 category by its identifier.

    Args:
        category_id: The category identifier (e.g. ``"LLM01"``).  The lookup
            is case-insensitive and tolerates leading/trailing whitespace.

    Returns:
        The corresponding :class:`OwaspLlmItem`, or ``None`` if the identifier
        is not recognised.
    """
    return OWASP_LLM_TOP_10.get(category_id.strip().upper())


def map_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group a list of findings by their OWASP LLM Top 10 category.

    Each :class:`~aisec.core.models.Finding` may reference zero or more
    OWASP LLM categories via its ``owasp_llm`` field.  This function
    builds a mapping from each referenced category identifier to the
    findings associated with it.

    Args:
        findings: Security findings to categorise.

    Returns:
        A dictionary whose keys are OWASP LLM category identifiers
        (e.g. ``"LLM01"``) and whose values are the lists of findings
        mapped to that category.  Categories with no associated findings
        are omitted from the result.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        for category_id in finding.owasp_llm:
            normalised = category_id.strip().upper()
            if normalised in OWASP_LLM_TOP_10:
                grouped.setdefault(normalised, []).append(finding)
    return grouped
