"""Target profiles for known AI agent frameworks.

Provides pre-built scanning configurations for popular AI agent
frameworks like AutoGPT, CrewAI, LangChain, and others.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aisec.core.config import AiSecConfig


@dataclass
class TargetProfile:
    """Pre-built scanning configuration for a specific AI agent framework."""

    name: str                                          # Profile name (e.g., "autogpt")
    display_name: str                                  # Human-readable name
    description: str                                   # What this profile targets
    agents: list[str] = field(default_factory=list)    # Recommended agents to enable
    skip_agents: list[str] = field(default_factory=list)  # Agents to skip (not relevant)
    compliance_frameworks: list[str] = field(default_factory=list)  # Relevant compliance frameworks
    detection_patterns: list[str] = field(default_factory=list)    # Patterns to auto-detect framework


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

BUILT_IN_PROFILES: dict[str, TargetProfile] = {
    "autogpt": TargetProfile(
        name="autogpt",
        display_name="AutoGPT / AgentGPT",
        description=(
            "Profile for AutoGPT and AgentGPT autonomous agent systems. "
            "Emphasises permission boundaries, adversarial robustness, "
            "prompt injection resistance, and supply-chain integrity."
        ),
        agents=["permission", "adversarial", "prompt_security", "supply_chain"],
        skip_agents=["model_scan", "sbom"],
        compliance_frameworks=["owasp_llm", "nist_ai"],
        detection_patterns=["autogpt", "agentgpt", "forge"],
    ),
    "crewai": TargetProfile(
        name="crewai",
        display_name="CrewAI",
        description=(
            "Profile for CrewAI multi-agent orchestration framework. "
            "Focuses on cascade failure analysis, permission scoping, "
            "and prompt security across cooperating agents."
        ),
        agents=["cascade", "permission", "prompt_security"],
        skip_agents=["model_scan", "sbom", "crypto"],
        compliance_frameworks=["owasp_llm", "nist_ai"],
        detection_patterns=["crewai", "crew_ai", "CrewBase"],
    ),
    "langchain": TargetProfile(
        name="langchain",
        display_name="LangChain Agents",
        description=(
            "Profile for LangChain agent pipelines. Targets prompt "
            "injection vectors, output validation, guardrail coverage, "
            "and adversarial robustness of tool-calling chains."
        ),
        agents=["prompt_security", "output", "guardrail", "adversarial"],
        skip_agents=["model_scan", "sbom"],
        compliance_frameworks=["owasp_llm", "nist_ai", "gdpr"],
        detection_patterns=["langchain", "LangChain", "AgentExecutor"],
    ),
    "llamaindex": TargetProfile(
        name="llamaindex",
        display_name="LlamaIndex",
        description=(
            "Profile for LlamaIndex data-augmented generation pipelines. "
            "Emphasises dataflow integrity, prompt injection resistance, "
            "and supply-chain security of index artefacts."
        ),
        agents=["dataflow", "prompt_security", "supply_chain"],
        skip_agents=["model_scan", "cascade", "crypto"],
        compliance_frameworks=["owasp_llm", "gdpr", "ccpa"],
        detection_patterns=["llama_index", "llamaindex", "LlamaIndex"],
    ),
    "openai_assistants": TargetProfile(
        name="openai_assistants",
        display_name="OpenAI Assistants API",
        description=(
            "Profile for applications built on the OpenAI Assistants API. "
            "Covers prompt security, output validation, network exposure, "
            "and cryptographic handling of API keys and tokens."
        ),
        agents=["prompt_security", "output", "network", "crypto"],
        skip_agents=["model_scan", "sbom", "cascade"],
        compliance_frameworks=["owasp_llm", "gdpr", "ccpa"],
        detection_patterns=["openai", "assistants", "gpt-4"],
    ),
    "huggingface": TargetProfile(
        name="huggingface",
        display_name="HuggingFace Models",
        description=(
            "Profile for HuggingFace Transformers model deployments. "
            "Prioritises model binary scanning, supply-chain provenance, "
            "SBOM generation, and adversarial input testing."
        ),
        agents=["model_scan", "supply_chain", "sbom", "adversarial"],
        skip_agents=["cascade", "network", "crypto"],
        compliance_frameworks=["owasp_llm", "nist_ai", "eu_ai_act"],
        detection_patterns=["transformers", "huggingface", "AutoModel"],
    ),
    "full": TargetProfile(
        name="full",
        display_name="Full Security Assessment",
        description=(
            "Comprehensive security assessment that enables every available "
            "agent and evaluates against all supported compliance frameworks. "
            "Use this for thorough audits where scan time is not a constraint."
        ),
        agents=["all"],
        skip_agents=[],
        compliance_frameworks=[
            "owasp_llm", "nist_ai", "gdpr", "ccpa",
            "habeas_data", "eu_ai_act",
        ],
        detection_patterns=[],
    ),
    "quick": TargetProfile(
        name="quick",
        display_name="Quick Scan",
        description=(
            "Lightweight scan that runs only the fastest, highest-signal "
            "agents. Ideal for CI pipelines and rapid triage where speed "
            "matters more than exhaustive coverage."
        ),
        agents=["prompt_security", "permission", "supply_chain", "dataflow"],
        skip_agents=[
            "model_scan", "sbom", "adversarial", "cascade",
            "crypto", "network", "guardrail",
        ],
        compliance_frameworks=["owasp_llm"],
        detection_patterns=[],
    ),
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_profile(name: str) -> TargetProfile | None:
    """Return a built-in profile by name, or ``None`` if not found."""
    return BUILT_IN_PROFILES.get(name)


def list_profiles() -> list[TargetProfile]:
    """Return all built-in profiles."""
    return list(BUILT_IN_PROFILES.values())


def detect_profile(files: dict[str, str]) -> TargetProfile | None:
    """Auto-detect the most appropriate profile from source file contents.

    Parameters
    ----------
    files:
        Mapping of file paths to their textual content.  The function
        searches every value for known detection patterns and returns the
        profile with the most pattern hits.

    Returns
    -------
    TargetProfile | None
        The best-matching profile, or ``None`` if nothing matched.
    """
    combined_text = "\n".join(files.values())

    best_profile: TargetProfile | None = None
    best_hits = 0

    for profile in BUILT_IN_PROFILES.values():
        if not profile.detection_patterns:
            continue
        hits = sum(1 for pat in profile.detection_patterns if pat in combined_text)
        if hits > best_hits:
            best_hits = hits
            best_profile = profile

    return best_profile


def apply_profile(config: AiSecConfig, profile: TargetProfile) -> AiSecConfig:
    """Return a new :class:`AiSecConfig` with the profile's settings applied.

    Profile values *override* the existing config for ``agents``,
    ``skip_agents``, and ``compliance_frameworks``.  All other config
    fields are preserved as-is.
    """
    data: dict[str, object] = {
        k: getattr(config, k)
        for k in config.model_fields
    }

    if profile.agents:
        data["agents"] = profile.agents
    if profile.skip_agents:
        data["skip_agents"] = profile.skip_agents
    if profile.compliance_frameworks:
        data["compliance_frameworks"] = profile.compliance_frameworks

    from aisec.core.config import AiSecConfig as _Cfg
    return _Cfg(**data)  # type: ignore[arg-type]
