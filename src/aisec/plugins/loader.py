"""Plugin discovery, loading, and hook dispatch via entry_points."""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

from aisec.plugins.interface import AiSecPlugin

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "aisec.plugins"


def discover_plugins() -> list[AiSecPlugin]:
    """Discover and load all installed AiSec plugins."""
    plugins: list[AiSecPlugin] = []
    eps = importlib.metadata.entry_points()
    aisec_eps = eps.select(group=ENTRY_POINT_GROUP) if hasattr(eps, "select") else eps.get(ENTRY_POINT_GROUP, [])

    for ep in aisec_eps:
        try:
            plugin_cls = ep.load()
            plugin = plugin_cls()
            if isinstance(plugin, AiSecPlugin):
                plugins.append(plugin)
                logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
            else:
                logger.warning("Entry point %s does not implement AiSecPlugin", ep.name)
        except Exception:
            logger.exception("Failed to load plugin: %s", ep.name)

    return plugins


class PluginManager:
    """Manages plugin lifecycle and hook dispatch.

    All hook invocations are error-isolated: a failing plugin will be
    logged but will never crash the scan.
    """

    def __init__(self, plugins: list[AiSecPlugin] | None = None) -> None:
        self._plugins = plugins if plugins is not None else discover_plugins()

    @property
    def plugins(self) -> list[AiSecPlugin]:
        return list(self._plugins)

    def call_pre_scan(self, context: Any) -> None:
        """Invoke pre_scan hook on all plugins."""
        for plugin in self._plugins:
            if hasattr(plugin, "pre_scan"):
                try:
                    plugin.pre_scan(context)
                except Exception:
                    logger.exception("Plugin %s pre_scan hook failed", getattr(plugin, "name", "unknown"))

    def call_post_scan(self, context: Any, report: Any) -> None:
        """Invoke post_scan hook on all plugins."""
        for plugin in self._plugins:
            if hasattr(plugin, "post_scan"):
                try:
                    plugin.post_scan(context, report)
                except Exception:
                    logger.exception("Plugin %s post_scan hook failed", getattr(plugin, "name", "unknown"))

    def call_on_finding(self, finding: Any) -> Any | None:
        """Invoke on_finding hook. Returns None to suppress the finding."""
        result = finding
        for plugin in self._plugins:
            if hasattr(plugin, "on_finding"):
                try:
                    result = plugin.on_finding(result)
                    if result is None:
                        logger.debug("Plugin %s suppressed finding", getattr(plugin, "name", "unknown"))
                        return None
                except Exception:
                    logger.exception("Plugin %s on_finding hook failed", getattr(plugin, "name", "unknown"))
        return result

    def call_modify_report(self, report: Any) -> Any:
        """Invoke modify_report hook. Plugins can mutate the report."""
        result = report
        for plugin in self._plugins:
            if hasattr(plugin, "modify_report"):
                try:
                    result = plugin.modify_report(result)
                except Exception:
                    logger.exception("Plugin %s modify_report hook failed", getattr(plugin, "name", "unknown"))
        return result
