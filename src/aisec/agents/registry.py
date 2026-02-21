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
    ):
        default_registry.register(agent_cls)

    logger.info("Registered %d core agents", len(default_registry.get_all()))
