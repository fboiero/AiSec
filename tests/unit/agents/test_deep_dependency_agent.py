"""Tests for DeepDependencyAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.deep_dependency import (
    COPYLEFT_LICENSES,
    RESTRICTIVE_LICENSES,
    DeepDependencyAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestDeepDependencyMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert DeepDependencyAgent.name == "deep_dependency"

    def test_phase(self):
        assert DeepDependencyAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM03" in DeepDependencyAgent.frameworks
        assert "ASI04" in DeepDependencyAgent.frameworks

    def test_depends_on(self):
        assert "dependency_audit" in DeepDependencyAgent.depends_on


class TestLicenseDefinitions:
    """Test license classification."""

    def test_copyleft_licenses(self):
        assert "GPL-3.0" in COPYLEFT_LICENSES
        assert "AGPL-3.0" in COPYLEFT_LICENSES
        assert "LGPL-3.0" in COPYLEFT_LICENSES

    def test_restrictive_licenses(self):
        assert "AGPL-3.0" in RESTRICTIVE_LICENSES
        assert "SSPL-1.0" in RESTRICTIVE_LICENSES


class TestDeepDependencyNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_fallback(self, scan_context):
        agent = DeepDependencyAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert "unavailable" in agent.findings[0].title.lower()


class TestDependencyTree:
    """Test dependency tree analysis."""

    def test_flatten_tree(self, scan_context):
        agent = DeepDependencyAgent(scan_context)
        tree = [
            {
                "package_name": "requests",
                "dependencies": [
                    {
                        "package_name": "urllib3",
                        "dependencies": [
                            {"package_name": "cryptography", "dependencies": []}
                        ],
                    },
                    {"package_name": "certifi", "dependencies": []},
                ],
            },
        ]
        result: dict[str, int] = {}
        agent._flatten_tree(tree, result, depth=0)
        assert result["requests"] == 0
        assert result["urllib3"] == 1
        assert result["cryptography"] == 2
        assert result["certifi"] == 1

    def test_flatten_tree_depth_limit(self, scan_context):
        """Test recursion protection."""
        agent = DeepDependencyAgent(scan_context)
        # Create a very deep tree
        tree = [{"package_name": "root", "dependencies": []}]
        current = tree[0]
        for i in range(25):
            child = {"package_name": f"dep_{i}", "dependencies": []}
            current["dependencies"] = [child]
            current = child

        result: dict[str, int] = {}
        agent._flatten_tree(tree, result, depth=0)
        # Should stop at depth 20
        assert max(result.values()) <= 20


class TestLicenseCompatibility:
    """Test license compatibility checking."""

    def test_detects_agpl_in_deps(self, scan_context):
        agent = DeepDependencyAgent(scan_context)
        licenses = [
            {"Name": "my-package", "License": "AGPL-3.0"},
            {"Name": "safe-package", "License": "MIT"},
        ]
        agent._check_license_compatibility(licenses)
        restrictive_findings = [
            f for f in agent.findings if "restrictive" in f.title.lower()
        ]
        assert len(restrictive_findings) >= 1

    def test_no_findings_for_permissive(self, scan_context):
        agent = DeepDependencyAgent(scan_context)
        licenses = [
            {"Name": "pkg1", "License": "MIT"},
            {"Name": "pkg2", "License": "Apache-2.0"},
            {"Name": "pkg3", "License": "BSD-3-Clause"},
        ]
        agent._check_license_compatibility(licenses)
        license_findings = [
            f for f in agent.findings
            if "license" in f.title.lower() and "unknown" not in f.title.lower()
        ]
        assert len(license_findings) == 0

    def test_unknown_licenses_flagged(self, scan_context):
        agent = DeepDependencyAgent(scan_context)
        licenses = [
            {"Name": f"pkg{i}", "License": "UNKNOWN"} for i in range(5)
        ]
        agent._check_license_compatibility(licenses)
        unknown_findings = [
            f for f in agent.findings if "unknown" in f.title.lower()
        ]
        assert len(unknown_findings) >= 1


class TestPipdeptreeIntegration:
    """Test pipdeptree integration."""

    @pytest.mark.asyncio
    async def test_pipdeptree_unavailable(self, scan_context):
        scan_context.container_id = "test-container"
        agent = DeepDependencyAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_pipdeptree()

        assert result is None
