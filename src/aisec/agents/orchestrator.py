"""DAG-based orchestrator for running agents in dependency order."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from aisec.agents.base import BaseAgent
from aisec.core.models import AgentResult

if TYPE_CHECKING:
    from aisec.agents.registry import AgentRegistry
    from aisec.core.context import ScanContext

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """Orchestrates agent execution respecting dependency order.

    Agents with no unmet dependencies are run concurrently via
    ``asyncio.gather``. When an agent completes, any agents whose
    dependencies are now fully satisfied are scheduled next.
    """

    def __init__(self, context: ScanContext, registry: AgentRegistry) -> None:
        self.context = context
        self.registry = registry

    # ------------------------------------------------------------------
    # DAG building
    # ------------------------------------------------------------------

    def build_dag(
        self, agents: dict[str, type[BaseAgent]]
    ) -> list[list[str]]:
        """Topologically sort agents into layers for parallel execution.

        Each layer contains agents whose dependencies are fully resolved
        by previous layers. Returns a list of layers, where each layer is
        a list of agent names that can be run concurrently.

        Raises ``ValueError`` if a circular dependency is detected.
        """
        # Adjacency: agent -> set of agents it depends on (within the
        # enabled set only -- external deps are ignored).
        in_degree: dict[str, int] = {}
        dependents: dict[str, list[str]] = defaultdict(list)

        available_names = set(agents.keys())

        for name, cls in agents.items():
            # Only count dependencies that are in the current agent set
            deps_in_set = [d for d in cls.depends_on if d in available_names]
            in_degree[name] = len(deps_in_set)
            for dep in deps_in_set:
                dependents[dep].append(name)

        # Kahn's algorithm -- produces layers
        layers: list[list[str]] = []
        queue: deque[str] = deque(
            name for name, deg in in_degree.items() if deg == 0
        )

        processed = 0
        while queue:
            layer = list(queue)
            queue.clear()
            layers.append(layer)
            processed += len(layer)
            for name in layer:
                for dep_name in dependents.get(name, []):
                    in_degree[dep_name] -= 1
                    if in_degree[dep_name] == 0:
                        queue.append(dep_name)

        if processed != len(agents):
            unresolved = [n for n, d in in_degree.items() if d > 0]
            raise ValueError(
                f"Circular dependency detected among agents: {unresolved}"
            )

        return layers

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run_scan(self) -> list[AgentResult]:
        """Execute the full scan respecting the dependency DAG.

        1. Retrieve enabled agents from the registry.
        2. Build the execution DAG (topological layers).
        3. Run each layer concurrently.
        4. Store results in ``context.agent_results``.
        5. Return all results.
        """
        config = self.context.config
        if config is None:
            enabled = self.registry.get_all()
        else:
            enabled = self.registry.get_enabled(config)

        if not enabled:
            logger.warning("No agents enabled for this scan")
            return []

        layers = self.build_dag(enabled)
        logger.info(
            "Execution plan: %d layers, %d agents",
            len(layers),
            sum(len(l) for l in layers),
        )

        all_results: list[AgentResult] = []

        for layer_idx, layer in enumerate(layers):
            logger.info(
                "Starting layer %d/%d: %s",
                layer_idx + 1,
                len(layers),
                ", ".join(layer),
            )

            tasks = []
            for agent_name in layer:
                agent_cls = enabled[agent_name]
                agent_instance = agent_cls(self.context)
                tasks.append(self._run_agent(agent_instance))

            layer_results = await asyncio.gather(*tasks)

            for result in layer_results:
                self.context.agent_results[result.agent] = result
                all_results.append(result)
                self.context.event_bus.emit("agent.completed", result)

        logger.info(
            "Scan complete: %d agents, %d total findings",
            len(all_results),
            sum(len(r.findings) for r in all_results),
        )
        return all_results

    async def _run_agent(self, agent: BaseAgent) -> AgentResult:
        """Run a single agent, catching any unexpected errors."""
        try:
            return await agent.run()
        except Exception as exc:
            logger.exception(
                "Unexpected error running agent %s", agent.name
            )
            return AgentResult(
                agent=agent.name,
                error=str(exc),
            )
