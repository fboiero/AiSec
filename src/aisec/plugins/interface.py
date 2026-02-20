"""Plugin interface protocol."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aisec.agents.registry import AgentRegistry


@runtime_checkable
class AiSecPlugin(Protocol):
    """Protocol that all AiSec plugins must implement."""

    name: str
    version: str
    description: str

    def register_agents(self, registry: AgentRegistry) -> None:
        """Register custom agents with the agent registry."""
        ...
