"""Structured logging configuration using structlog."""

from __future__ import annotations

import logging
import os
import sys

import structlog


def setup_logging(level: str = "INFO", json_format: bool | None = None) -> None:
    """Configure structured logging for AiSec.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: Force JSON output. If None, uses AISEC_LOG_FORMAT env var.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Determine output format
    if json_format is None:
        env_json = os.environ.get("AISEC_LOG_JSON", "").lower()
        env_format = os.environ.get("AISEC_LOG_FORMAT", "human").lower()
        json_format = env_json in ("true", "1", "yes") or env_format == "json"

    # Shared processors for both structlog and stdlib
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger("aisec")
    root.handlers.clear()
    root.setLevel(log_level)
    root.addHandler(handler)


def bind_context(**kwargs: object) -> None:
    """Bind key-value pairs to the structlog context for the current context.

    Useful for injecting request IDs, scan IDs, etc.
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear all bound structlog context variables."""
    structlog.contextvars.clear_contextvars()


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger bound to the given name."""
    return structlog.get_logger(name)
