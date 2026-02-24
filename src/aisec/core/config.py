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

    # Cloud storage
    cloud_storage_backend: str = Field(default="", description="Cloud storage backend (s3, gcs, azure)")
    cloud_storage_bucket: str = Field(default="", description="Cloud storage bucket name")
    cloud_storage_prefix: str = Field(default="aisec-reports/", description="Key prefix for uploaded reports")

    # Falco runtime monitoring
    falco_enabled: bool = Field(default=False, description="Enable Falco sidecar for runtime monitoring")
    falco_image: str = Field(default="falcosecurity/falco-no-driver:latest", description="Falco container image")

    # Logging
    log_level: str = "INFO"
    log_format: str = Field(default="human", description="Log format: human or json")

    # Scheduler
    schedule_cron: str = Field(default="", description="Cron expression for scheduled scans")
    schedule_image: str = Field(default="", description="Docker image for scheduled scans")
    log_format: str = Field(default="human", description="Log format: human or json")

    # Scheduler
    schedule_cron: str = Field(default="", description="Cron expression for scheduled scans")
    schedule_image: str = Field(default="", description="Docker image for scheduled scans")

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
        "cloud.storage_backend": "cloud_storage_backend",
        "cloud.storage_bucket": "cloud_storage_bucket",
        "cloud.storage_prefix": "cloud_storage_prefix",
        "falco.enabled": "falco_enabled",
        "falco.image": "falco_image",
        "logging.level": "log_level",
        "logging.format": "log_format",
        "scheduler.cron": "schedule_cron",
        "scheduler.image": "schedule_image",
    }
    for key, value in data.items():
        full_key = f"{prefix}{key}" if prefix else key
        if isinstance(value, dict):
            _flatten(value, out, prefix=f"{full_key}.")
        elif full_key in key_map:
            out[key_map[full_key]] = value
