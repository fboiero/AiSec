"""Tests for the plugin system."""

from aisec.plugins.interface import AiSecPlugin
from aisec.plugins.loader import discover_plugins
from aisec.plugins.hooks import HookSpec


def test_discover_plugins_returns_list():
    # With no external plugins installed, should return empty list
    plugins = discover_plugins()
    assert isinstance(plugins, list)


def test_plugin_protocol():
    """Verify the plugin protocol can be implemented."""

    class MyPlugin:
        name = "test-plugin"
        version = "1.0.0"
        description = "Test plugin"

        def register_agents(self, registry):
            pass

    plugin = MyPlugin()
    assert isinstance(plugin, AiSecPlugin)
    assert plugin.name == "test-plugin"
    assert plugin.version == "1.0.0"


def test_hook_spec_defaults():
    hooks = HookSpec()
    assert hooks.pre_scan is None or callable(hooks.pre_scan) or hooks.pre_scan is None
