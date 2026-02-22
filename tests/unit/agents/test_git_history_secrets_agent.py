"""Tests for GitHistorySecretsAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.git_history_secrets import (
    SECRET_PATTERNS,
    GitHistorySecretsAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestGitHistorySecretsMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert GitHistorySecretsAgent.name == "git_history_secrets"

    def test_phase(self):
        assert GitHistorySecretsAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM01" in GitHistorySecretsAgent.frameworks
        assert "ASI04" in GitHistorySecretsAgent.frameworks

    def test_no_dependencies(self):
        assert GitHistorySecretsAgent.depends_on == []


class TestSecretPatterns:
    """Test built-in secret patterns."""

    def test_patterns_not_empty(self):
        assert len(SECRET_PATTERNS) > 10

    def test_pattern_structure(self):
        for name, pattern, severity in SECRET_PATTERNS:
            assert isinstance(name, str)
            assert hasattr(pattern, "search")
            assert isinstance(severity, Severity)

    def test_openai_key_pattern(self):
        _, pattern, _ = SECRET_PATTERNS[0]  # OpenAI
        assert pattern.search("sk-abcdefghijklmnopqrstuvwxyz1234567890")

    def test_anthropic_key_pattern(self):
        _, pattern, _ = SECRET_PATTERNS[1]  # Anthropic
        assert pattern.search("sk-ant-abcdefghijklmnopqrstuvwxyz1234567890")

    def test_aws_key_pattern(self):
        _, pattern, _ = SECRET_PATTERNS[3]  # AWS
        assert pattern.search("AKIAIOSFODNN7EXAMPLE")

    def test_private_key_pattern(self):
        _, pattern, _ = SECRET_PATTERNS[5]  # Private key
        assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert pattern.search("-----BEGIN PRIVATE KEY-----")

    def test_connection_string_pattern(self):
        _, pattern, _ = SECRET_PATTERNS[6]  # Connection string
        assert pattern.search("postgresql://user:pass@host/db")
        assert pattern.search("mongodb://admin:secret@localhost/mydb")


class TestGitHistorySecretsNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = GitHistorySecretsAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO
        assert "No git" in agent.findings[0].title

    @pytest.mark.asyncio
    async def test_no_git_directory(self, scan_context):
        scan_context.container_id = "test-container"
        agent = GitHistorySecretsAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            await agent.analyze()

        assert len(agent.findings) == 1
        assert "No git" in agent.findings[0].title


class TestGitleaksIntegration:
    """Test gitleaks integration."""

    @pytest.mark.asyncio
    async def test_gitleaks_unavailable_falls_back(self, scan_context):
        scan_context.container_id = "test-container"
        agent = GitHistorySecretsAgent(scan_context)

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:  # check git dir
                proc.returncode = 0
            elif call_count == 2:  # gitleaks version
                raise FileNotFoundError("gitleaks not found")
            else:  # git log fallback
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"no secrets here\n", b""))
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent.analyze()


class TestGitleaksFindings:
    """Test gitleaks finding processing."""

    def test_process_gitleaks_findings(self, scan_context):
        agent = GitHistorySecretsAgent(scan_context)
        findings = [
            {
                "RuleID": "openai-api-key",
                "Secret": "sk-1234567890abcdef",
                "File": "config.py",
                "StartLine": 5,
                "Commit": "abc12345",
                "Author": "dev@example.com",
                "Date": "2024-01-01",
                "Description": "OpenAI API key detected",
            },
        ]
        agent._process_gitleaks_findings(findings)
        assert len(agent.findings) == 1
        assert "openai-api-key" in agent.findings[0].title

    def test_deduplicates_findings(self, scan_context):
        agent = GitHistorySecretsAgent(scan_context)
        findings = [
            {
                "RuleID": "openai-api-key",
                "Secret": "sk-same-key-in-both",
                "File": "config.py",
                "StartLine": 5,
                "Commit": "abc12345",
                "Author": "dev@example.com",
                "Date": "2024-01-01",
            },
            {
                "RuleID": "openai-api-key",
                "Secret": "sk-same-key-in-both",
                "File": "config.py",
                "StartLine": 5,
                "Commit": "def67890",
                "Author": "dev@example.com",
                "Date": "2024-01-02",
            },
        ]
        agent._process_gitleaks_findings(findings)
        assert len(agent.findings) == 1
