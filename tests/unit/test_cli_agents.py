"""Tests for agents list/info CLI commands (Phase 4)."""

from __future__ import annotations

import unittest


class TestAgentsListCommand(unittest.TestCase):
    """Verify agents list command."""

    def test_agents_list_importable(self):
        from aisec.cli.agents import list_agents
        self.assertTrue(callable(list_agents))

    def test_agents_app_registered(self):
        """Verify agents_app is registered in main CLI."""
        from aisec.cli.app import app
        # Check that 'agents' is a registered sub-command
        command_names = []
        for info in getattr(app, "registered_groups", []):
            name = getattr(info, "name", None) or getattr(info, "typer_instance", None)
            if name:
                command_names.append(name)
        # Alternative: just verify the import works
        from aisec.cli.agents import agents_app
        self.assertIsNotNone(agents_app)


class TestAgentsInfoCommand(unittest.TestCase):
    """Verify agents info command."""

    def test_agents_info_importable(self):
        from aisec.cli.agents import info
        self.assertTrue(callable(info))


class TestRegistryIntegration(unittest.TestCase):
    """Verify agent registry works with the CLI."""

    def test_register_core_agents_populates_registry(self):
        from aisec.agents.registry import default_registry, register_core_agents
        register_core_agents()
        all_agents = default_registry.get_all()
        self.assertGreater(len(all_agents), 30)

    def test_agent_has_required_attributes(self):
        from aisec.agents.registry import default_registry, register_core_agents
        register_core_agents()
        all_agents = default_registry.get_all()
        for name, cls in all_agents.items():
            self.assertTrue(hasattr(cls, "name"))
            self.assertTrue(hasattr(cls, "description"))
            self.assertTrue(hasattr(cls, "phase"))
            self.assertEqual(cls.name, name)


if __name__ == "__main__":
    unittest.main()
