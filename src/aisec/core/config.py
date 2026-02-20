"""Configuration system with YAML/env/CLI layering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class AiSecConfig(BaseSettings):
    """AiSec configuration with layered loading: defaults -> YAML -> env -> CLI."""

    # Target
    target_image: str = ""
    target_name: str = ""
    target_type: str = "generic"

    # Scan
    scan_timeout: int = Field(default=3600, description="Max scan duration in seconds")
    agents: list[str] = Field(default=["all"], description="Agents to run")
    skip_agents: list[str] = Field(default=[], description="Agents to skip")

    # Docker
    docker_host: str = "unix:///var/run/docker.sock"
    container_memory_limit: str = "2g"
    container_cpu_limit: float = 1.0

    # Report
    report_formats: list[str] = Field(default=["json", "html"])
    report_language: str = "en"
    report_output_dir: str = "./aisec-reports"

    # Compliance
    compliance_frameworks: list[str] = Field(default=["gdpr", "ccpa", "habeas_data"])

    # Plugins
    plugin_dirs: list[str] = Field(default=[])
    disabled_plugins: list[str] = Field(default=[])

    # Logging
    log_level: str = "INFO"

    model_config = {"env_prefix": "AISEC_"}

    @classmethod
    def from_yaml(cls, path: str | Path, **overrides: Any) -> AiSecConfig:
        """Load configuration from a YAML file with optional overrides."""
        config_path = Path(path)
        if not config_path.exists():
            return cls(**overrides)

        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}

        flat: dict[str, Any] = {}
        _flatten(raw, flat)
        flat.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**flat)


def _flatten(data: dict[str, Any], out: dict[str, Any], prefix: str = "") -> None:
    """Flatten nested YAML dict into top-level keys matching config field names."""
    key_map = {
        "target.image": "target_image",
        "target.name": "target_name",
        "target.type": "target_type",
        "scan.timeout": "scan_timeout",
        "scan.agents": "agents",
        "scan.skip_agents": "skip_agents",
        "docker.host": "docker_host",
        "docker.memory_limit": "container_memory_limit",
        "docker.cpu_limit": "container_cpu_limit",
        "report.format": "report_formats",
        "report.language": "report_language",
        "report.output_dir": "report_output_dir",
        "compliance.frameworks": "compliance_frameworks",
        "plugins.dirs": "plugin_dirs",
        "plugins.disabled": "disabled_plugins",
        "logging.level": "log_level",
    }
    for key, value in data.items():
        full_key = f"{prefix}{key}" if prefix else key
        if isinstance(value, dict):
            _flatten(value, out, prefix=f"{full_key}.")
        elif full_key in key_map:
            out[key_map[full_key]] = value
