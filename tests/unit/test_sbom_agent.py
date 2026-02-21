"""Tests for SBOMAgent."""

import pytest

from aisec.agents.sbom import SBOMAgent, _MANIFEST_FILES, _SBOM_PATTERNS, _COPYLEFT_LICENSES, _PERMISSIVE_LICENSES
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase
from aisec.utils.parsers import Dependency


# ── Agent metadata ──────────────────────────────────────────────────

def test_sbom_agent_name():
    assert SBOMAgent.name == "sbom"


def test_sbom_agent_phase():
    assert SBOMAgent.phase == AgentPhase.STATIC


def test_sbom_agent_depends_on_supply_chain():
    assert "supply_chain" in SBOMAgent.depends_on


def test_sbom_agent_frameworks():
    assert "LLM03" in SBOMAgent.frameworks


# ── Manifest file constants ─────────────────────────────────────────

def test_manifest_files_includes_requirements():
    assert "requirements.txt" in _MANIFEST_FILES


def test_manifest_files_includes_package_json():
    assert "package.json" in _MANIFEST_FILES


def test_manifest_files_includes_go_sum():
    assert "go.sum" in _MANIFEST_FILES


def test_manifest_files_includes_cargo_lock():
    assert "Cargo.lock" in _MANIFEST_FILES


# ── SBOM patterns ───────────────────────────────────────────────────

def test_sbom_patterns_include_cyclonedx():
    cyclonedx_patterns = [fmt for _, fmt in _SBOM_PATTERNS if fmt == "CycloneDX"]
    assert len(cyclonedx_patterns) >= 3


def test_sbom_patterns_include_spdx():
    spdx_patterns = [fmt for _, fmt in _SBOM_PATTERNS if fmt == "SPDX"]
    assert len(spdx_patterns) >= 2


# ── License constants ──────────────────────────────────────────────

def test_copyleft_includes_gpl3():
    assert "GPL-3.0" in _COPYLEFT_LICENSES or "GPL-3.0-only" in _COPYLEFT_LICENSES


def test_copyleft_includes_agpl():
    assert "AGPL-3.0" in _COPYLEFT_LICENSES or "AGPL-3.0-only" in _COPYLEFT_LICENSES


def test_permissive_includes_mit():
    assert "MIT" in _PERMISSIVE_LICENSES


def test_permissive_includes_apache():
    assert "Apache-2.0" in _PERMISSIVE_LICENSES


# ── Parsers (invoked internally) ────────────────────────────────────

def test_parse_pipfile_lock():
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    pipfile_content = '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}'
    agent._parse_pipfile_lock(pipfile_content)
    assert any(d.name == "requests" for d in agent._dependencies)


def test_parse_poetry_lock():
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    poetry_content = """[[package]]
name = "click"
version = "8.1.7"

[[package]]
name = "rich"
version = "13.7.0"
"""
    agent._parse_poetry_lock(poetry_content)
    names = [d.name for d in agent._dependencies]
    assert "click" in names
    assert "rich" in names


def test_parse_go_sum():
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    go_sum = "github.com/stretchr/testify v1.8.4 h1:abc123\ngithub.com/stretchr/testify v1.8.4/go.mod h1:def456\n"
    agent._parse_go_sum(go_sum)
    assert any(d.name == "github.com/stretchr/testify" for d in agent._dependencies)


def test_parse_cargo_lock():
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    cargo_content = """[[package]]
name = "serde"
version = "1.0.193"

[[package]]
name = "tokio"
version = "1.35.0"
"""
    agent._parse_cargo_lock(cargo_content)
    names = [d.name for d in agent._dependencies]
    assert "serde" in names
    assert "tokio" in names


def test_parse_gemfile_lock():
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    gemfile_content = """GEM
  specs:
    rails (7.1.0)
    puma (6.4.0)

PLATFORMS
"""
    agent._parse_gemfile_lock(gemfile_content)
    names = [d.name for d in agent._dependencies]
    assert "rails" in names
    assert "puma" in names


# ── PURL generation ─────────────────────────────────────────────────

def test_build_purl_pypi():
    dep = Dependency(name="requests", version="2.31.0", pinned=True, source="requirements.txt")
    purl = SBOMAgent._build_purl(dep)
    assert purl == "pkg:pypi/requests@2.31.0"


def test_build_purl_npm():
    dep = Dependency(name="express", version="4.18.2", pinned=True, source="package.json")
    purl = SBOMAgent._build_purl(dep)
    assert purl == "pkg:npm/express@4.18.2"


def test_build_purl_golang():
    dep = Dependency(name="github.com/gin-gonic/gin", version="1.9.1", pinned=True, source="go.sum")
    purl = SBOMAgent._build_purl(dep)
    assert purl == "pkg:golang/github.com/gin-gonic/gin@1.9.1"


def test_build_purl_cargo():
    dep = Dependency(name="serde", version="1.0.193", pinned=True, source="Cargo.lock")
    purl = SBOMAgent._build_purl(dep)
    assert purl == "pkg:cargo/serde@1.0.193"


# ── Agent instantiation ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_sbom_agent_run_returns_result():
    """Agent.run() should return an AgentResult even without Docker."""
    ctx = ScanContext(target_image="test:latest")
    agent = SBOMAgent(ctx)
    result = await agent.run()
    assert result.agent == "sbom"
    assert result.error is None


# ── Measure pip depth ──────────────────────────────────────────────

def test_measure_pip_depth_flat():
    node = {"package": {"key": "a"}, "dependencies": []}
    assert SBOMAgent._measure_pip_depth(node, 0) == 0


def test_measure_pip_depth_nested():
    node = {
        "package": {"key": "a"},
        "dependencies": [
            {
                "package": {"key": "b"},
                "dependencies": [
                    {"package": {"key": "c"}, "dependencies": []},
                ],
            }
        ],
    }
    assert SBOMAgent._measure_pip_depth(node, 0) == 2
