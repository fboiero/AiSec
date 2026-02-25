"""AiSec exception hierarchy."""

from __future__ import annotations


class AiSecError(Exception):
    """Base exception for all AiSec errors."""


class ConfigError(AiSecError):
    """Configuration-related errors."""


class DockerError(AiSecError):
    """Docker operation errors."""


class ScanError(AiSecError):
    """Scan execution errors."""


class AgentError(AiSecError):
    """Agent execution errors."""

    def __init__(self, agent_name: str, message: str) -> None:
        self.agent_name = agent_name
        super().__init__(f"[{agent_name}] {message}")


class ReportError(AiSecError):
    """Report generation errors."""


class PluginError(AiSecError):
    """Plugin loading or execution errors."""


class ScanTimeoutError(ScanError):
    """Scan exceeded the configured timeout."""


class WebhookError(AiSecError):
    """Webhook registration or delivery errors."""


class QueueFullError(AiSecError):
    """Scan queue is at capacity."""

    def __init__(self, queue_size: int, max_size: int) -> None:
        self.queue_size = queue_size
        self.max_size = max_size
        super().__init__(
            f"Scan queue full ({queue_size}/{max_size}). Try again later."
        )


class ValidationError(AiSecError):
    """Input validation errors (e.g., SSRF-blocked URL)."""

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(f"Validation error on '{field}': {message}")


def error_response(code: str, message: str, details: dict | None = None) -> dict:
    """Build a structured API error response body."""
    resp: dict = {"error": {"code": code, "message": message}}
    if details:
        resp["error"]["details"] = details
    return resp
