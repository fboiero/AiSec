"""Plugin discovery and loading via entry_points."""

from __future__ import annotations

import importlib.metadata
import logging

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
