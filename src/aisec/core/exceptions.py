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
