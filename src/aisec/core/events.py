"""Simple event bus for inter-agent communication."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Callable

logger = logging.getLogger(__name__)


class EventBus:
    """Lightweight publish/subscribe event bus."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[..., Any]]] = defaultdict(list)

    def on(self, event: str, handler: Callable[..., Any]) -> None:
        """Register a handler for an event."""
        self._handlers[event].append(handler)

    def emit(self, event: str, *args: Any, **kwargs: Any) -> None:
        """Emit an event, calling all registered handlers."""
        for handler in self._handlers.get(event, []):
            try:
                handler(*args, **kwargs)
            except Exception:
                logger.exception("Error in event handler for %s", event)

    def clear(self) -> None:
        """Remove all event handlers."""
        self._handlers.clear()
