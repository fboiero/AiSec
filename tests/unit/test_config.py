"""Tests for configuration system."""

import tempfile
from pathlib import Path

from aisec.core.config import AiSecConfig


def test_default_config():
    cfg = AiSecConfig()
    assert cfg.target_image == ""
    assert cfg.scan_timeout == 3600
    assert cfg.report_language == "en"
    assert "gdpr" in cfg.compliance_frameworks


def test_config_with_overrides():
    cfg = AiSecConfig(
        target_image="myagent:latest",
        scan_timeout=600,
        report_language="es",
    )
    assert cfg.target_image == "myagent:latest"
    assert cfg.scan_timeout == 600
    assert cfg.report_language == "es"


def test_config_from_yaml():
    yaml_content = """
target:
  image: "test:latest"
  name: "TestAgent"
  type: "openclaw"
scan:
  timeout: 1800
report:
  language: "es"
  format: ["json", "pdf"]
compliance:
  frameworks: ["gdpr", "habeas_data"]
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        f.flush()
        cfg = AiSecConfig.from_yaml(f.name)

    assert cfg.target_image == "test:latest"
    assert cfg.target_name == "TestAgent"
    assert cfg.target_type == "openclaw"
    assert cfg.scan_timeout == 1800
    assert cfg.report_language == "es"


def test_config_from_yaml_nonexistent():
    cfg = AiSecConfig.from_yaml("/nonexistent/path.yaml", target_image="fallback:latest")
    assert cfg.target_image == "fallback:latest"


def test_config_from_yaml_with_overrides():
    yaml_content = """
target:
  image: "original:latest"
scan:
  timeout: 3600
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        f.flush()
        cfg = AiSecConfig.from_yaml(f.name, target_image="override:latest")

    assert cfg.target_image == "override:latest"
