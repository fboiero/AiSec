"""Tests for DependencyAuditAgent."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.dependency_audit import (
    KNOWN_MALICIOUS_PACKAGES,
    POPULAR_AI_PACKAGES,
    DependencyAuditAgent,
    _levenshtein_distance,
)
from aisec.core.enums import AgentPhase, Severity


class TestDependencyAuditAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert DependencyAuditAgent.name == "dependency_audit"

    def test_phase(self):
        assert DependencyAuditAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM03" in DependencyAuditAgent.frameworks
        assert "ASI04" in DependencyAuditAgent.frameworks

    def test_depends_on(self):
        assert "supply_chain" in DependencyAuditAgent.depends_on


class TestLevenshteinDistance:
    """Test the Levenshtein distance function."""

    def test_identical_strings(self):
        assert _levenshtein_distance("hello", "hello") == 0

    def test_empty_strings(self):
        assert _levenshtein_distance("", "") == 0
        assert _levenshtein_distance("hello", "") == 5
        assert _levenshtein_distance("", "hello") == 5

    def test_single_substitution(self):
        assert _levenshtein_distance("cat", "car") == 1

    def test_single_insertion(self):
        assert _levenshtein_distance("cat", "cats") == 1

    def test_single_deletion(self):
        assert _levenshtein_distance("cats", "cat") == 1

    def test_typosquatting_example(self):
        # "transfomers" is 1 edit from "transformers"
        assert _levenshtein_distance("transfomers", "transformers") == 1

    def test_different_strings(self):
        assert _levenshtein_distance("abc", "xyz") == 3


class TestConstants:
    """Test agent constants."""

    def test_popular_packages_populated(self):
        assert len(POPULAR_AI_PACKAGES) >= 10
        assert "transformers" in POPULAR_AI_PACKAGES
        assert "torch" in POPULAR_AI_PACKAGES
        assert "openai" in POPULAR_AI_PACKAGES

    def test_malicious_packages_populated(self):
        assert len(KNOWN_MALICIOUS_PACKAGES) >= 30
        assert "python-openai" in KNOWN_MALICIOUS_PACKAGES


class TestNoContainer:
    """Test agent behavior without a container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = DependencyAuditAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert "No dependency files" in agent.findings[0].title

    @pytest.mark.asyncio
    async def test_no_dep_files_found(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DependencyAuditAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            await agent.analyze()

        assert len(agent.findings) == 1
        assert "No dependency files" in agent.findings[0].title


class TestTyposquattingDetection:
    """Test typosquatting detection."""

    @pytest.mark.asyncio
    async def test_detects_typosquat(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("transfomers", "1.0.0"),  # typo of "transformers"
            ("opennai", "1.0.0"),  # typo of "openai"
        ]

        await agent._check_typosquatting(packages)

        typosquat_findings = [
            f for f in agent.findings if "typosquatting" in f.title.lower()
        ]
        assert len(typosquat_findings) == 1
        assert typosquat_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_exact_match_not_flagged(self, scan_context):
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("transformers", "4.0.0"),
            ("torch", "2.0.0"),
            ("openai", "1.0.0"),
        ]

        await agent._check_typosquatting(packages)
        assert len(agent.findings) == 0


class TestMaliciousPackageDetection:
    """Test malicious package detection."""

    @pytest.mark.asyncio
    async def test_detects_malicious_package(self, scan_context):
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("python-openai", "1.0.0"),
            ("transformers", "4.0.0"),
        ]

        await agent._check_malicious_packages(packages)

        mal_findings = [
            f for f in agent.findings if "malicious" in f.title.lower()
        ]
        assert len(mal_findings) == 1
        assert mal_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_clean_packages_not_flagged(self, scan_context):
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("transformers", "4.0.0"),
            ("torch", "2.0.0"),
        ]

        await agent._check_malicious_packages(packages)
        assert len(agent.findings) == 0


class TestPinningCheck:
    """Test dependency pinning checks."""

    @pytest.mark.asyncio
    async def test_unpinned_deps_flagged(self, scan_context):
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("flask", "unpinned"),
            ("requests", "unpinned"),
            ("numpy", "unpinned"),
            ("pandas", "unpinned"),
        ]

        await agent._check_pinning(packages, ["requirements.txt"])

        pin_findings = [
            f for f in agent.findings if "Unpinned" in f.title
        ]
        assert len(pin_findings) == 1
        assert pin_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_pinned_deps_not_flagged(self, scan_context):
        agent = DependencyAuditAgent(scan_context)

        packages = [
            ("flask", "2.0.0"),
            ("requests", "2.28.0"),
        ]

        await agent._check_pinning(packages, ["requirements.txt"])
        assert len(agent.findings) == 0


class TestPipAuditIntegration:
    """Test pip-audit integration."""

    @pytest.mark.asyncio
    async def test_pip_audit_unavailable(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DependencyAuditAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_pip_audit()

        assert result is False

    @pytest.mark.asyncio
    async def test_pip_audit_with_vulns(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DependencyAuditAgent(scan_context)

        pip_audit_output = json.dumps({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-001",
                            "description": "CRITICAL vuln in requests",
                            "fix_versions": ["2.31.0"],
                            "cvss": 9.5,
                        }
                    ],
                }
            ]
        })

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:  # version check in container
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"2.7.0", b""))
            else:  # actual audit
                proc.returncode = 0
                proc.communicate = AsyncMock(
                    return_value=(pip_audit_output.encode(), b"")
                )
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await agent._run_pip_audit()

        assert result is True
        assert len(agent.findings) == 1
        assert "requests" in agent.findings[0].title
        assert agent.findings[0].severity == Severity.CRITICAL


class TestDependencyParsing:
    """Test dependency file parsing."""

    @pytest.mark.asyncio
    async def test_parse_requirements_txt(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DependencyAuditAgent(scan_context)

        requirements = (
            "flask==2.0.0\n"
            "requests>=2.28.0\n"
            "numpy\n"
            "# comment\n"
            "pandas==1.5.0\n"
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(requirements, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            packages = await agent._parse_dependencies(
                ["/app/requirements.txt"]
            )

        assert len(packages) >= 3
        names = [p[0] for p in packages]
        assert "flask" in names
        assert "numpy" in names
