"""Tests for AgentRegistry."""

import pytest

from aisec.agents.base import BaseAgent
from aisec.agents.registry import AgentRegistry, register_core_agents, default_registry
from aisec.core.config import AiSecConfig
from aisec.core.enums import AgentPhase, Severity


class DummyAgent(BaseAgent):
    name = "dummy"
    description = "Dummy agent for testing"
    phase = AgentPhase.STATIC

    async def analyze(self):
        pass


class AnotherAgent(BaseAgent):
    name = "another"
    description = "Another dummy"
    phase = AgentPhase.DYNAMIC

    async def analyze(self):
        pass


def test_register_and_get():
    reg = AgentRegistry()
    reg.register(DummyAgent)
    assert reg.get("dummy") is DummyAgent


def test_get_nonexistent():
    reg = AgentRegistry()
    assert reg.get("nope") is None


def test_get_all():
    reg = AgentRegistry()
    reg.register(DummyAgent)
    reg.register(AnotherAgent)
    all_agents = reg.get_all()
    assert "dummy" in all_agents
    assert "another" in all_agents
    assert len(all_agents) == 2


def test_get_enabled_all():
    reg = AgentRegistry()
    reg.register(DummyAgent)
    reg.register(AnotherAgent)
    cfg = AiSecConfig(agents=["all"])
    enabled = reg.get_enabled(cfg)
    assert len(enabled) == 2


def test_get_enabled_specific():
    reg = AgentRegistry()
    reg.register(DummyAgent)
    reg.register(AnotherAgent)
    cfg = AiSecConfig(agents=["dummy"])
    enabled = reg.get_enabled(cfg)
    assert len(enabled) == 1
    assert "dummy" in enabled


def test_get_enabled_skip():
    reg = AgentRegistry()
    reg.register(DummyAgent)
    reg.register(AnotherAgent)
    cfg = AiSecConfig(agents=["all"], skip_agents=["dummy"])
    enabled = reg.get_enabled(cfg)
    assert "dummy" not in enabled
    assert "another" in enabled


def test_register_core_agents():
    register_core_agents()
    all_agents = default_registry.get_all()
    expected = {"network", "dataflow", "privacy", "prompt_security", "supply_chain", "permission", "output"}
    assert expected.issubset(set(all_agents.keys()))


def test_register_empty_name_raises():
    class BadAgent(BaseAgent):
        name = ""
        description = "bad"
        phase = AgentPhase.STATIC

        async def analyze(self):
            pass

    reg = AgentRegistry()
    with pytest.raises(ValueError, match="non-empty"):
        reg.register(BadAgent)
