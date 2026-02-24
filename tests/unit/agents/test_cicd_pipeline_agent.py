"""Tests for CICDPipelineSecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.cicd_pipeline import (
    BRANCH_PROTECTION_PATTERNS,
    CI_SECRET_PATTERNS,
    CI_SECRET_REF_PATTERNS,
    DEPLOY_STEP_PATTERNS,
    DOCKER_PRIVILEGED_PATTERNS,
    DOWNLOAD_VERIFY_PATTERNS,
    INSECURE_DOWNLOAD_PATTERNS,
    LATEST_TAG_PATTERNS,
    UNSAFE_PIP_PATTERNS,
    VULN_SCAN_PATTERNS,
    CICDPipelineSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestCICDPipelineMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert CICDPipelineSecurityAgent.name == "cicd_pipeline"

    def test_phase(self):
        assert CICDPipelineSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM05" in CICDPipelineSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert CICDPipelineSecurityAgent.depends_on == []


class TestCICDPatterns:
    """Test regex pattern matching."""

    def test_ci_secret_patterns_match(self):
        assert CI_SECRET_PATTERNS.search("sk-abcdefghijklmnopqrstuvwxyz")
        assert CI_SECRET_PATTERNS.search("hf_abcdefghijklmnopqrstuvwxyz")

    def test_insecure_download_matches(self):
        assert INSECURE_DOWNLOAD_PATTERNS.search("wget https://example.com/model.bin")
        assert INSECURE_DOWNLOAD_PATTERNS.search("curl -o model.bin https://example.com/model")

    def test_docker_privileged_matches(self):
        assert DOCKER_PRIVILEGED_PATTERNS.search("--privileged")
        assert DOCKER_PRIVILEGED_PATTERNS.search("privileged: true")


class TestCICDNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestSecretsInCI:
    """Test secrets in CI config detection."""

    def test_detects_secrets_in_yaml(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/train.yml": (
                'name: Train Model\n'
                'env:\n'
                '  HF_TOKEN: hf_abcdefghijklmnopqrstuvwxyz\n'
                '  OPENAI_KEY: sk-abcdefghijklmnopqrstuvwxyz\n'
                'jobs:\n'
                '  train:\n'
                '    runs-on: ubuntu-latest\n'
            )
        }
        agent._check_secrets_in_configs(files)
        findings = [f for f in agent.findings if "Secrets" in f.title]
        assert len(findings) >= 1

    def test_ci_secret_reference_passes(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/train.yml": (
                'name: Train Model\n'
                'env:\n'
                '  HF_TOKEN: ${{ secrets.HF_TOKEN }}\n'
                '  OPENAI_KEY: ${{ secrets.OPENAI_KEY }}\n'
                'jobs:\n'
                '  train:\n'
                '    runs-on: ubuntu-latest\n'
            )
        }
        agent._check_secrets_in_configs(files)
        findings = [f for f in agent.findings if "Secrets" in f.title]
        assert len(findings) == 0


class TestInsecureModelDownload:
    """Test insecure model download detection."""

    def test_detects_insecure_download(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/deploy.yml": (
                'steps:\n'
                '  - name: Download model\n'
                '    run: wget https://huggingface.co/model/resolve/model.bin\n'
            )
        }
        agent._check_insecure_downloads(files)
        findings = [f for f in agent.findings if "download" in f.title.lower()]
        assert len(findings) >= 1

    def test_download_with_checksum_passes(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/deploy.yml": (
                'steps:\n'
                '  - name: Download model\n'
                '    run: |\n'
                '      wget https://huggingface.co/model/resolve/model.bin\n'
                '      sha256sum --check model.sha256\n'
            )
        }
        agent._check_insecure_downloads(files)
        findings = [f for f in agent.findings if "download" in f.title.lower()]
        assert len(findings) == 0


class TestUnsafePipInstall:
    """Test unsafe pip install detection."""

    def test_detects_unsafe_pip(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/build.yml": (
                'steps:\n'
                '  - name: Install deps\n'
                '    run: pip install --trusted-host pypi.internal.com\n'
            )
        }
        agent._check_unsafe_pip(files)
        findings = [f for f in agent.findings if "pip" in f.title.lower()]
        assert len(findings) >= 1


class TestNoVulnScanning:
    """Test missing vulnerability scanning detection."""

    def test_detects_no_vuln_scanning(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        combined = (
            'name: Build\n'
            'jobs:\n'
            '  build:\n'
            '    steps:\n'
            '      - run: python setup.py install\n'
            '      - run: pytest tests/\n'
        )
        agent._check_no_vuln_scanning(combined)
        findings = [f for f in agent.findings if "scanning" in f.title.lower()]
        assert len(findings) >= 1


class TestDockerPrivileged:
    """Test Docker privileged mode detection."""

    def test_detects_docker_privileged(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/build.yml": (
                'jobs:\n'
                '  train:\n'
                '    container:\n'
                '      image: pytorch/pytorch:latest\n'
                '      options: --privileged\n'
            )
        }
        agent._check_docker_privileged(files)
        findings = [f for f in agent.findings if "privileged" in f.title.lower()]
        assert len(findings) >= 1


class TestUnversionedDeploy:
    """Test unversioned :latest deployment detection."""

    def test_detects_latest_tag(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/deploy.yml": (
                'steps:\n'
                '  - run: docker push myregistry/model:latest\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unversioned_deploy(files, combined)
        findings = [f for f in agent.findings if "Unversioned" in f.title or ":latest" in f.title]
        assert len(findings) >= 1


class TestMissingBranchProtection:
    """Test missing branch protection detection."""

    def test_detects_missing_branch_protection(self, scan_context):
        agent = CICDPipelineSecurityAgent(scan_context)
        files = {
            "/app/.github/workflows/deploy.yml": (
                'name: Deploy\n'
                'on: push\n'
                'jobs:\n'
                '  deploy:\n'
                '    steps:\n'
                '      - run: kubectl apply -f deployment.yaml\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_missing_branch_protection(files, combined)
        findings = [f for f in agent.findings if "branch" in f.title.lower()]
        assert len(findings) >= 1
