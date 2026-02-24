"""Agent registry for discovering and managing analysis agents."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aisec.agents.base import BaseAgent

if TYPE_CHECKING:
    from aisec.core.config import AiSecConfig

logger = logging.getLogger(__name__)


class AgentRegistry:
    """Registry of available security analysis agents."""

    def __init__(self) -> None:
        self._agents: dict[str, type[BaseAgent]] = {}

    def register(self, agent_cls: type[BaseAgent]) -> type[BaseAgent]:
        """Register an agent class. Can be used as a decorator."""
        name = agent_cls.name
        if not name:
            raise ValueError(f"Agent class {agent_cls.__name__} must define a non-empty 'name' attribute")
        if name in self._agents:
            logger.warning("Overwriting existing agent registration: %s", name)
        self._agents[name] = agent_cls
        logger.debug("Registered agent: %s (%s)", name, agent_cls.__name__)
        return agent_cls

    def get(self, name: str) -> type[BaseAgent] | None:
        """Retrieve a registered agent class by name."""
        return self._agents.get(name)

    def get_all(self) -> dict[str, type[BaseAgent]]:
        """Return all registered agent classes."""
        return dict(self._agents)

    def get_enabled(self, config: AiSecConfig) -> dict[str, type[BaseAgent]]:
        """Return agents filtered by config.agents and config.skip_agents.

        If config.agents contains 'all', all agents are included except those
        listed in config.skip_agents. Otherwise only the named agents are
        included (minus any in skip_agents).
        """
        if "all" in config.agents:
            candidates = dict(self._agents)
        else:
            candidates = {
                name: cls
                for name, cls in self._agents.items()
                if name in config.agents
            }

        # Remove skipped agents
        for skip_name in config.skip_agents:
            candidates.pop(skip_name, None)

        return candidates


# Module-level default registry instance
default_registry = AgentRegistry()


def register_core_agents() -> None:
    """Import and register all built-in agents with the default registry."""
    # Import each agent module to trigger class definitions, then register them.
    from aisec.agents.network import NetworkAgent
    from aisec.agents.dataflow import DataFlowAgent
    from aisec.agents.privacy import PrivacyAgent
    from aisec.agents.prompt_security import PromptSecurityAgent
    from aisec.agents.supply_chain import SupplyChainAgent
    from aisec.agents.permission import PermissionAgent
    from aisec.agents.output import OutputAgent
    from aisec.agents.crypto import CryptoAuditAgent
    from aisec.agents.sbom import SBOMAgent
    from aisec.agents.garak_agent import GarakAgent
    from aisec.agents.guardrails import GuardrailAgent
    from aisec.agents.model_scan import ModelScanAgent
    from aisec.agents.adversarial import AdversarialAgent
    from aisec.agents.cascade import CascadeAgent
    from aisec.agents.synthetic_content import SyntheticContentAgent
    from aisec.agents.static_analysis import StaticAnalysisAgent
    from aisec.agents.dependency_audit import DependencyAuditAgent
    from aisec.agents.api_security import APISecurityAgent
    from aisec.agents.iac_security import IaCSecurityAgent
    from aisec.agents.runtime_behavior import RuntimeBehaviorAgent
    from aisec.agents.taint_analysis import TaintAnalysisAgent
    from aisec.agents.serialization import SerializationAgent
    from aisec.agents.git_history_secrets import GitHistorySecretsAgent
    from aisec.agents.deep_dependency import DeepDependencyAgent
    from aisec.agents.resource_exhaustion import ResourceExhaustionAgent
    from aisec.agents.inter_service import InterServiceSecurityAgent
    from aisec.agents.data_lineage import DataLineagePrivacyAgent
    from aisec.agents.embedding_leakage import EmbeddingLeakageAgent
    from aisec.agents.rag_security import RAGSecurityAgent
    from aisec.agents.mcp_security import MCPSecurityAgent
    from aisec.agents.tool_chain import ToolChainSecurityAgent
    from aisec.agents.agent_memory import AgentMemorySecurityAgent
    from aisec.agents.fine_tuning import FineTuningSecurityAgent
    from aisec.agents.cicd_pipeline import CICDPipelineSecurityAgent

    for agent_cls in (
        NetworkAgent,
        DataFlowAgent,
        PrivacyAgent,
        PromptSecurityAgent,
        SupplyChainAgent,
        PermissionAgent,
        OutputAgent,
        CryptoAuditAgent,
        SBOMAgent,
        GarakAgent,
        GuardrailAgent,
        ModelScanAgent,
        AdversarialAgent,
        CascadeAgent,
        SyntheticContentAgent,
        StaticAnalysisAgent,
        DependencyAuditAgent,
        APISecurityAgent,
        IaCSecurityAgent,
        RuntimeBehaviorAgent,
        TaintAnalysisAgent,
        SerializationAgent,
        GitHistorySecretsAgent,
        DeepDependencyAgent,
        ResourceExhaustionAgent,
        InterServiceSecurityAgent,
        DataLineagePrivacyAgent,
        EmbeddingLeakageAgent,
        RAGSecurityAgent,
        MCPSecurityAgent,
        ToolChainSecurityAgent,
        AgentMemorySecurityAgent,
        FineTuningSecurityAgent,
        CICDPipelineSecurityAgent,
    ):
        default_registry.register(agent_cls)

    logger.info("Registered %d core agents", len(default_registry.get_all()))
