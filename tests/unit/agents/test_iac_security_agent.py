"""Tests for IaCSecurityAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.iac_security import (
    DOCKERFILE_CHECKS,
    K8S_CHECKS,
    IaCSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestIaCSecurityAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert IaCSecurityAgent.name == "iac_security"

    def test_phase(self):
        assert IaCSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM03" in IaCSecurityAgent.frameworks
        assert "ASI04" in IaCSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert IaCSecurityAgent.depends_on == []


class TestConstants:
    """Test agent constants."""

    def test_dockerfile_checks_populated(self):
        assert len(DOCKERFILE_CHECKS) >= 7

    def test_k8s_checks_populated(self):
        assert len(K8S_CHECKS) >= 5

    def test_check_structure(self):
        for name, pattern, severity, desc, rem in DOCKERFILE_CHECKS:
            assert isinstance(name, str)
            assert hasattr(pattern, "search")
            assert isinstance(severity, Severity)
            assert isinstance(desc, str)
            assert isinstance(rem, str)


class TestNoContainer:
    """Test agent behavior without IaC files."""

    @pytest.mark.asyncio
    async def test_no_iac_files(self, scan_context):
        scan_context.container_id = "test-container"
        agent = IaCSecurityAgent(scan_context)

        with patch.object(agent, "_extract_dockerfile", return_value=""):
            with patch.object(agent, "_find_k8s_manifests", return_value=[]):
                with patch.object(agent, "_find_compose_files", return_value=[]):
                    await agent.analyze()

        assert len(agent.findings) >= 1
        info_findings = [f for f in agent.findings if "No IaC" in f.title]
        assert len(info_findings) == 1


class TestDockerfileChecks:
    """Test built-in Dockerfile security checks."""

    @pytest.mark.asyncio
    async def test_no_user_directive(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:3.11-slim\n"
            "COPY . /app\n"
            "RUN pip install -r requirements.txt\n"
            "CMD [\"python\", \"app.py\"]\n"
        )

        await agent._check_dockerfile(dockerfile)

        user_findings = [
            f for f in agent.findings
            if "root" in f.title.lower() or "USER" in f.title
        ]
        assert len(user_findings) >= 1

    @pytest.mark.asyncio
    async def test_latest_tag(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:latest\n"
            "USER nonroot\n"
            "HEALTHCHECK CMD curl localhost\n"
            "COPY . /app\n"
        )

        await agent._check_dockerfile(dockerfile)

        latest_findings = [
            f for f in agent.findings if ":latest" in f.title
        ]
        assert len(latest_findings) == 1
        assert latest_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_secrets_in_env(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:3.11\n"
            "USER app\n"
            "HEALTHCHECK CMD true\n"
            "ENV SECRET_KEY=mysecret123\n"
            "ENV API_KEY=sk-test\n"
        )

        await agent._check_dockerfile(dockerfile)

        secret_findings = [
            f for f in agent.findings if "Secrets" in f.title or "SECRET" in f.title
        ]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_healthcheck(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:3.11\n"
            "USER app\n"
            "COPY . /app\n"
        )

        await agent._check_dockerfile(dockerfile)

        health_findings = [
            f for f in agent.findings if "HEALTHCHECK" in f.title
        ]
        assert len(health_findings) >= 1

    @pytest.mark.asyncio
    async def test_sensitive_ports(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:3.11\n"
            "USER app\n"
            "HEALTHCHECK CMD true\n"
            "EXPOSE 22\n"
            "EXPOSE 6379\n"
        )

        await agent._check_dockerfile(dockerfile)

        port_findings = [
            f for f in agent.findings if "port" in f.title.lower()
        ]
        assert len(port_findings) >= 1

    @pytest.mark.asyncio
    async def test_clean_dockerfile(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        dockerfile = (
            "FROM python:3.11-slim@sha256:abc123\n"
            "USER 1000:1000\n"
            "HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health\n"
            "COPY requirements.txt /app/\n"
            "RUN pip install --no-cache-dir -r /app/requirements.txt\n"
            "COPY . /app\n"
            "EXPOSE 8080\n"
            "CMD [\"python\", \"/app/main.py\"]\n"
        )

        await agent._check_dockerfile(dockerfile)

        # Should have no high+ severity findings for a well-configured Dockerfile
        high_findings = [
            f for f in agent.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(high_findings) == 0


class TestKubernetesChecks:
    """Test built-in Kubernetes manifest security checks."""

    @pytest.mark.asyncio
    async def test_privileged_container(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  containers:\n"
            "  - name: ai-agent\n"
            "    securityContext:\n"
            "      privileged: true\n"
        )

        await agent._check_k8s_manifest("/deploy/pod.yaml", manifest)

        priv_findings = [
            f for f in agent.findings if "Privileged" in f.title
        ]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_host_network(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  hostNetwork: true\n"
            "  containers:\n"
            "  - name: ai-agent\n"
            "    securityContext:\n"
            "      runAsNonRoot: true\n"
            "    resources:\n"
            "      limits:\n"
            "        memory: 512Mi\n"
        )

        await agent._check_k8s_manifest("/deploy/pod.yaml", manifest)

        host_findings = [
            f for f in agent.findings if "Host network" in f.title
        ]
        assert len(host_findings) == 1
        assert host_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_run_as_root(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  containers:\n"
            "  - name: ai-agent\n"
            "    securityContext:\n"
            "      runAsUser: 0\n"
            "    resources:\n"
            "      limits:\n"
            "        memory: 512Mi\n"
        )

        await agent._check_k8s_manifest("/deploy/pod.yaml", manifest)

        root_findings = [
            f for f in agent.findings if "root" in f.title.lower()
        ]
        assert len(root_findings) >= 1


class TestCheckovIntegration:
    """Test Checkov integration."""

    @pytest.mark.asyncio
    async def test_checkov_unavailable(self, scan_context):
        agent = IaCSecurityAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_checkov("FROM python:3.11", [])

        assert result is False
