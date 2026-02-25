"""Tests for plugin hook dispatch via PluginManager."""

from unittest.mock import MagicMock

from aisec.plugins.loader import PluginManager


def _make_plugin(**hooks):
    """Create a mock plugin with specified hooks."""
    plugin = MagicMock()
    plugin.name = "test-plugin"
    plugin.version = "1.0"
    # Remove all hook attrs by default, then add requested ones
    for hook in ("pre_scan", "post_scan", "on_finding", "modify_report"):
        if hook not in hooks:
            delattr(plugin, hook)
        else:
            setattr(plugin, hook, hooks[hook])
    return plugin


class TestPluginManagerInit:
    def test_no_plugins(self):
        pm = PluginManager(plugins=[])
        assert pm.plugins == []

    def test_with_plugins(self):
        p = _make_plugin()
        pm = PluginManager(plugins=[p])
        assert len(pm.plugins) == 1


class TestPreScan:
    def test_hook_called(self):
        hook = MagicMock()
        p = _make_plugin(pre_scan=hook)
        pm = PluginManager(plugins=[p])
        pm.call_pre_scan({"target": "test"})
        hook.assert_called_once_with({"target": "test"})

    def test_hook_error_isolated(self):
        hook = MagicMock(side_effect=RuntimeError("boom"))
        p = _make_plugin(pre_scan=hook)
        pm = PluginManager(plugins=[p])
        # Should not raise
        pm.call_pre_scan({"target": "test"})

    def test_no_hook_method(self):
        p = _make_plugin()
        pm = PluginManager(plugins=[p])
        # Should not raise even without pre_scan attr
        pm.call_pre_scan({"target": "test"})


class TestPostScan:
    def test_hook_called(self):
        hook = MagicMock()
        p = _make_plugin(post_scan=hook)
        pm = PluginManager(plugins=[p])
        pm.call_post_scan({"ctx": True}, {"report": True})
        hook.assert_called_once_with({"ctx": True}, {"report": True})

    def test_error_isolated(self):
        hook = MagicMock(side_effect=ValueError("bad"))
        p = _make_plugin(post_scan=hook)
        pm = PluginManager(plugins=[p])
        pm.call_post_scan({}, {})


class TestOnFinding:
    def test_passthrough(self):
        pm = PluginManager(plugins=[])
        finding = {"title": "test", "severity": "high"}
        result = pm.call_on_finding(finding)
        assert result == finding

    def test_suppression(self):
        hook = MagicMock(return_value=None)
        p = _make_plugin(on_finding=hook)
        pm = PluginManager(plugins=[p])
        result = pm.call_on_finding({"title": "suppress me"})
        assert result is None

    def test_modification(self):
        def modify(finding):
            finding = dict(finding)
            finding["severity"] = "critical"
            return finding

        p = _make_plugin(on_finding=modify)
        pm = PluginManager(plugins=[p])
        result = pm.call_on_finding({"title": "test", "severity": "high"})
        assert result["severity"] == "critical"

    def test_error_passes_through(self):
        hook = MagicMock(side_effect=RuntimeError("boom"))
        p = _make_plugin(on_finding=hook)
        pm = PluginManager(plugins=[p])
        finding = {"title": "test"}
        result = pm.call_on_finding(finding)
        # Finding should survive despite hook error
        assert result == finding


class TestModifyReport:
    def test_hook_called(self):
        hook = MagicMock(return_value={"modified": True})
        p = _make_plugin(modify_report=hook)
        pm = PluginManager(plugins=[p])
        result = pm.call_modify_report({"original": True})
        assert result == {"modified": True}

    def test_mutation(self):
        def add_meta(report):
            report["plugin_meta"] = "added"
            return report

        p = _make_plugin(modify_report=add_meta)
        pm = PluginManager(plugins=[p])
        result = pm.call_modify_report({"findings": []})
        assert result["plugin_meta"] == "added"

    def test_error_preserves_report(self):
        hook = MagicMock(side_effect=RuntimeError("crash"))
        p = _make_plugin(modify_report=hook)
        pm = PluginManager(plugins=[p])
        result = pm.call_modify_report({"data": 1})
        # Original report should be returned despite error
        assert result == {"data": 1}


class TestMultiplePlugins:
    def test_hook_chain(self):
        """Multiple plugins' on_finding hooks are chained."""
        def plugin1_hook(finding):
            finding = dict(finding)
            finding["plugin1"] = True
            return finding

        def plugin2_hook(finding):
            finding = dict(finding)
            finding["plugin2"] = True
            return finding

        p1 = _make_plugin(on_finding=plugin1_hook)
        p2 = _make_plugin(on_finding=plugin2_hook)
        pm = PluginManager(plugins=[p1, p2])
        result = pm.call_on_finding({"title": "test"})
        assert result["plugin1"] is True
        assert result["plugin2"] is True

    def test_failing_plugin_doesnt_block_others(self):
        """A failing plugin doesn't prevent subsequent plugins from running."""
        calls = []

        def good_hook(ctx):
            calls.append("good")

        bad_hook = MagicMock(side_effect=RuntimeError("bad"))

        p1 = _make_plugin(pre_scan=bad_hook)
        p2 = _make_plugin(pre_scan=good_hook)
        pm = PluginManager(plugins=[p1, p2])
        pm.call_pre_scan({})
        assert "good" in calls
