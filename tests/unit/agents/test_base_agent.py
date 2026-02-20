"""Tests for BaseAgent."""

import pytest

from aisec.agents.base import BaseAgent
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase, Severity
from aisec.core.events import EventBus


class MockAgent(BaseAgent):
    name = "mock_agent"
    description = "A mock agent for testing"
    phase = AgentPhase.DYNAMIC

    async def analyze(self) -> None:
        self.add_finding(
            title="Mock Finding",
            description="Found by mock agent",
            severity=Severity.MEDIUM,
            owasp_llm=["LLM01"],
        )


class FailingAgent(BaseAgent):
    name = "failing_agent"
    description = "An agent that fails"
    phase = AgentPhase.DYNAMIC

    async def analyze(self) -> None:
        raise RuntimeError("Analysis failed")


@pytest.mark.asyncio
async def test_agent_run(scan_context):
    agent = MockAgent(scan_context)
    result = await agent.run()
    assert result.agent == "mock_agent"
    assert len(result.findings) == 1
    assert result.findings[0].title == "Mock Finding"
    assert result.error is None
    assert result.duration_seconds > 0


@pytest.mark.asyncio
async def test_agent_failure(scan_context):
    agent = FailingAgent(scan_context)
    result = await agent.run()
    assert result.agent == "failing_agent"
    assert result.error is not None
    assert "Analysis failed" in result.error


@pytest.mark.asyncio
async def test_agent_finding_events(scan_context):
    events = []
    scan_context.event_bus.on("finding.new", lambda f: events.append(f))

    agent = MockAgent(scan_context)
    await agent.run()

    assert len(events) == 1
    assert events[0].title == "Mock Finding"


def test_add_finding(scan_context):
    agent = MockAgent(scan_context)
    finding = agent.add_finding(
        title="Test",
        description="Desc",
        severity=Severity.HIGH,
        owasp_llm=["LLM06"],
        remediation="Fix it",
    )
    assert finding.title == "Test"
    assert finding.agent == "mock_agent"
    assert len(agent.findings) == 1
