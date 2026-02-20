"""Tests for OrchestratorAgent."""

import pytest

from aisec.agents.base import BaseAgent
from aisec.agents.orchestrator import OrchestratorAgent
from aisec.agents.registry import AgentRegistry
from aisec.core.enums import AgentPhase, Severity


class AgentA(BaseAgent):
    name = "agent_a"
    description = "First agent"
    phase = AgentPhase.STATIC
    depends_on = []

    async def analyze(self):
        self.add_finding(title="Finding A", description="From A", severity=Severity.LOW)


class AgentB(BaseAgent):
    name = "agent_b"
    description = "Second agent, depends on A"
    phase = AgentPhase.DYNAMIC
    depends_on = ["agent_a"]

    async def analyze(self):
        # Verify agent_a results are available
        if "agent_a" in self.context.agent_results:
            self.add_finding(title="Finding B", description="From B, saw A", severity=Severity.MEDIUM)


class AgentC(BaseAgent):
    name = "agent_c"
    description = "Independent agent"
    phase = AgentPhase.DYNAMIC
    depends_on = []

    async def analyze(self):
        self.add_finding(title="Finding C", description="From C", severity=Severity.HIGH)


@pytest.mark.asyncio
async def test_orchestrator_runs_all_agents(scan_context):
    registry = AgentRegistry()
    registry.register(AgentA)
    registry.register(AgentB)
    registry.register(AgentC)

    orchestrator = OrchestratorAgent(scan_context, registry)
    results = await orchestrator.run_scan()

    assert "agent_a" in results
    assert "agent_b" in results
    assert "agent_c" in results
    assert len(results["agent_a"].findings) == 1
    assert len(results["agent_b"].findings) == 1
    assert len(results["agent_c"].findings) == 1


@pytest.mark.asyncio
async def test_orchestrator_respects_dependencies(scan_context):
    registry = AgentRegistry()
    registry.register(AgentA)
    registry.register(AgentB)

    orchestrator = OrchestratorAgent(scan_context, registry)
    results = await orchestrator.run_scan()

    # AgentB should have seen AgentA's results
    assert results["agent_b"].findings[0].description == "From B, saw A"
