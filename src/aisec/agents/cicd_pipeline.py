"""CI/CD pipeline security agent for AI/ML workloads."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Secrets in CI config patterns
CI_SECRET_PATTERNS = re.compile(
    r'(?:sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9]{20,}|'
    r'hf_[a-zA-Z0-9]{20,}|'
    r'AKIA[0-9A-Z]{16}|'
    r'wandb_[a-zA-Z0-9]{20,}|'
    r'ghp_[a-zA-Z0-9]{36}|'
    r'glpat-[a-zA-Z0-9\-]{20,}|'
    r'xoxb-[0-9]{10,}|'
    r'gcp_credentials|'
    r'(?:password|secret|token|api_key)\s*[:=]\s*["\'][^$\{][a-zA-Z0-9_\-]{8,}["\'])',
    re.IGNORECASE,
)

# Secret from CI variables (safe pattern)
CI_SECRET_REF_PATTERNS = re.compile(
    r'(?:\$\{\{?\s*secrets\.|'
    r'\$\{\{?\s*vars\.|'
    r'\$\{\{?\s*env\.|'
    r'\$[A-Z_]+|'
    r'vault://|'
    r'aws:secretsmanager|'
    r'gcloud secrets)',
    re.IGNORECASE,
)

# Insecure model download patterns (wget/curl without checksum)
INSECURE_DOWNLOAD_PATTERNS = re.compile(
    r'(?:wget\s+|curl\s+.*-[oOL]\s+|'
    r'huggingface-cli\s+download|'
    r'git\s+lfs\s+pull|'
    r'aws\s+s3\s+cp|'
    r'gsutil\s+cp|'
    r'az\s+storage\s+blob\s+download)',
)

# Download verification patterns
DOWNLOAD_VERIFY_PATTERNS = re.compile(
    r'(?:sha256|sha512|md5sum|checksum|verify|'
    r'--checksum|--hash|digest|integrity|'
    r'cosign\s+verify|sigstore)',
    re.IGNORECASE,
)

# Model signing patterns
MODEL_SIGN_PATTERNS = re.compile(
    r'(?:cosign\s+sign|sigstore|notation\s+sign|'
    r'gpg\s+--sign|sign.*model|model.*sign|'
    r'in-toto|slsa-verifier)',
    re.IGNORECASE,
)

# Model push / deploy patterns
MODEL_DEPLOY_PATTERNS = re.compile(
    r'(?:push_to_hub|docker\s+push|kubectl\s+apply|'
    r'aws\s+sagemaker|gcloud\s+ai|'
    r'az\s+ml.*deploy|mlflow.*deploy|'
    r'triton.*deploy|bentoml.*deploy)',
    re.IGNORECASE,
)

# Unsafe pip install patterns
UNSAFE_PIP_PATTERNS = re.compile(
    r'(?:pip\s+install.*--trusted-host|'
    r'pip\s+install.*--extra-index-url\s+http://|'
    r'pip\s+install.*--index-url\s+http://|'
    r'pip\s+install\s+--no-verify|'
    r'pip\s+install.*--disable-pip-version-check.*http://)',
    re.IGNORECASE,
)

# Exposed training infrastructure
EXPOSED_INFRA_PATTERNS = re.compile(
    r'(?:jupyter.*(?:--ip\s*=?\s*0\.0\.0\.0|--no-browser.*--port)|'
    r'tensorboard.*(?:--host\s*=?\s*0\.0\.0\.0|--bind_all)|'
    r'mlflow\s+server.*--host\s*=?\s*0\.0\.0\.0|'
    r'gpu.*endpoint|training.*endpoint|'
    r'notebook.*expose|gradio.*share\s*=\s*True)',
    re.IGNORECASE,
)

# Infrastructure auth patterns
INFRA_AUTH_PATTERNS = re.compile(
    r'(?:--password|--token|--auth|auth_enabled|'
    r'NotebookApp\.password|ServerApp\.password|'
    r'--certfile|ssl_cert|tls)',
    re.IGNORECASE,
)

# Unprotected artifact upload
ARTIFACT_UPLOAD_PATTERNS = re.compile(
    r'(?:upload-artifact|actions/upload-artifact|'
    r'artifacts\s*:|cache.*save|'
    r'store_artifacts|persist_to_workspace)',
    re.IGNORECASE,
)

# Artifact protection patterns
ARTIFACT_PROTECTION_PATTERNS = re.compile(
    r'(?:retention-days|retention_days|expire_in|'
    r'artifact.*encrypt|artifact.*sign|'
    r'if-no-files-found|overwrite)',
    re.IGNORECASE,
)

# Vulnerability scanning patterns
VULN_SCAN_PATTERNS = re.compile(
    r'(?:aisec|trivy|semgrep|bandit|safety|'
    r'snyk|dependabot|renovate|grype|'
    r'codeql|sonarqube|checkov|tfsec|'
    r'pip-audit|npm\s+audit|security.*scan)',
    re.IGNORECASE,
)

# Docker privileged patterns in CI
DOCKER_PRIVILEGED_PATTERNS = re.compile(
    r'(?:--privileged|privileged:\s*true|'
    r'--cap-add\s*=?\s*SYS_ADMIN|'
    r'--cap-add\s*=?\s*ALL|'
    r'securityContext.*privileged:\s*true)',
    re.IGNORECASE,
)

# Unversioned deployment patterns (using :latest)
LATEST_TAG_PATTERNS = re.compile(
    r'(?:image:\s*\S+:latest|'
    r'docker\s+(?:pull|run|push)\s+\S+:latest|'
    r'FROM\s+\S+:latest|'
    r'container_image.*:latest)',
    re.IGNORECASE,
)

# Versioned deployment indicators
VERSIONED_TAG_PATTERNS = re.compile(
    r'(?:image:\s*\S+:\$|'
    r':\$\{\{|'
    r'image:.*\$[A-Z_]*VERSION|'
    r'--tag\s+\S+:v?\d+|'
    r'sha256:|@sha256:)',
    re.IGNORECASE,
)

# Branch protection / deploy condition patterns
BRANCH_PROTECTION_PATTERNS = re.compile(
    r'(?:if:.*github\.ref\s*==|'
    r'branches:\s*\[.*main|'
    r'only:\s*\[.*main|'
    r'on:\s*\n\s*push:\s*\n\s*branches:|'
    r'when:\s*branch|'
    r'rules:\s*\n\s*-\s*if:.*branch|'
    r'environment:\s*\n\s*name:\s*production)',
    re.IGNORECASE,
)

# Deploy step indicators
DEPLOY_STEP_PATTERNS = re.compile(
    r'(?:deploy|release|publish|push.*prod|'
    r'kubectl\s+apply|helm\s+upgrade|'
    r'terraform\s+apply|aws.*deploy)',
    re.IGNORECASE,
)


class CICDPipelineSecurityAgent(BaseAgent):
    """Scans CI/CD pipeline configurations for AI/ML security risks."""

    name: ClassVar[str] = "cicd_pipeline"
    description: ClassVar[str] = (
        "Scans CI/CD pipeline configurations for AI/ML-specific security "
        "risks: secrets in configs, insecure model downloads, missing "
        "signing, unsafe pip install, and unprotected artifacts."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM05", "ASI04"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze CI/CD pipeline security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No CI/CD config files found",
                description="No CI/CD configuration files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM05"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:200]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        self._check_secrets_in_configs(all_content)
        self._check_insecure_downloads(all_content)
        self._check_missing_signing(all_content, combined)
        self._check_unsafe_pip(all_content)
        self._check_exposed_infra(all_content)
        self._check_unprotected_artifacts(all_content)
        self._check_no_vuln_scanning(combined)
        self._check_docker_privileged(all_content)
        self._check_unversioned_deploy(all_content, combined)
        self._check_missing_branch_protection(all_content, combined)

    def _check_secrets_in_configs(self, files: dict[str, str]) -> None:
        """Check for hardcoded secrets in CI configuration files."""
        ci_files = {
            f: c for f, c in files.items()
            if any(ext in f for ext in ('.yml', '.yaml', 'Jenkinsfile', 'Makefile', '.toml'))
        }
        for fpath, content in ci_files.items():
            secret_matches = list(CI_SECRET_PATTERNS.finditer(content))
            if not secret_matches:
                continue

            for match in secret_matches:
                context_start = max(0, match.start() - 100)
                context = content[context_start:match.end()]
                if CI_SECRET_REF_PATTERNS.search(context):
                    continue

                line = content[:match.start()].count("\n") + 1
                secret_preview = match.group()[:10] + "..."
                self.add_finding(
                    title="Secrets in CI/CD configuration",
                    description=(
                        f"Potential hardcoded secret at {fpath} (line {line}): "
                        f"{secret_preview}. Secrets in CI configs are exposed to "
                        "anyone with repository read access and may be logged in "
                        "build outputs."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_llm=["LLM05"],
                    owasp_agentic=["ASI04"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Hardcoded secret in CI config at {fpath}",
                        raw_data=f"Line: {line}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use CI/CD secret management: GitHub Actions secrets "
                        "(${{ secrets.KEY }}), GitLab CI variables, or external "
                        "secret stores (Vault, AWS Secrets Manager)."
                    ),
                    cvss_score=9.0,
                    ai_risk_score=8.0,
                )

    def _check_insecure_downloads(self, files: dict[str, str]) -> None:
        """Check for model/artifact downloads without checksum verification."""
        for fpath, content in files.items():
            download_matches = list(INSECURE_DOWNLOAD_PATTERNS.finditer(content))
            if not download_matches:
                continue

            has_verify = bool(DOWNLOAD_VERIFY_PATTERNS.search(content))
            if not has_verify:
                lines = [str(content[:m.start()].count("\n") + 1) for m in download_matches]
                self.add_finding(
                    title="Insecure model download without checksum",
                    description=(
                        f"Model/artifact download at {fpath} (lines: "
                        f"{', '.join(lines)}) without checksum or integrity "
                        "verification. A compromised download source or "
                        "man-in-the-middle attack could substitute a backdoored model."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM05"],
                    owasp_agentic=["ASI04"],
                    nist_ai_rmf=["GOVERN", "MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unverified download at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add checksum verification after downloads: "
                        "sha256sum --check model.sha256. Pin model versions "
                        "and verify with cosign or sigstore."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.5,
                )

    def _check_missing_signing(self, files: dict[str, str], combined: str) -> None:
        """Check for model push/deploy without signing."""
        has_deploy = bool(MODEL_DEPLOY_PATTERNS.search(combined))
        has_signing = bool(MODEL_SIGN_PATTERNS.search(combined))

        if has_deploy and not has_signing:
            self.add_finding(
                title="Missing model signing in CI/CD pipeline",
                description=(
                    "Models are pushed or deployed in the CI pipeline without "
                    "cryptographic signing. Without signing, there is no guarantee "
                    "that the deployed model was produced by the CI system and "
                    "has not been tampered with."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Sign model artifacts with cosign or sigstore before deployment. "
                    "Verify signatures in the deployment pipeline. Use SLSA "
                    "provenance for supply chain integrity."
                ),
                cvss_score=7.0,
                ai_risk_score=7.0,
            )

    def _check_unsafe_pip(self, files: dict[str, str]) -> None:
        """Check for unsafe pip install flags in CI."""
        for fpath, content in files.items():
            pip_matches = list(UNSAFE_PIP_PATTERNS.finditer(content))
            if not pip_matches:
                continue

            lines = [str(content[:m.start()].count("\n") + 1) for m in pip_matches]
            self.add_finding(
                title="Unsafe pip install in CI pipeline",
                description=(
                    f"Unsafe pip install at {fpath} (lines: {', '.join(lines)}) "
                    "using --trusted-host, --extra-index-url with HTTP, or "
                    "--no-verify. This enables dependency confusion and "
                    "man-in-the-middle attacks on the package supply chain."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary=f"Unsafe pip install at {fpath}",
                    raw_data=f"Lines: {', '.join(lines)}",
                    location=fpath,
                )],
                remediation=(
                    "Always use HTTPS for package indices. Remove --trusted-host "
                    "flags. Use pip install --require-hashes with pinned "
                    "dependencies for reproducible, verified installs."
                ),
                cvss_score=7.5,
                ai_risk_score=7.0,
            )

    def _check_exposed_infra(self, files: dict[str, str]) -> None:
        """Check for exposed training infrastructure in CI."""
        for fpath, content in files.items():
            infra_matches = list(EXPOSED_INFRA_PATTERNS.finditer(content))
            if not infra_matches:
                continue

            has_auth = bool(INFRA_AUTH_PATTERNS.search(content))
            if not has_auth:
                lines = [str(content[:m.start()].count("\n") + 1) for m in infra_matches]
                self.add_finding(
                    title="Exposed training infrastructure without auth",
                    description=(
                        f"Training infrastructure exposed at {fpath} (lines: "
                        f"{', '.join(lines)}) — Jupyter, TensorBoard, or ML endpoints "
                        "bound to 0.0.0.0 without authentication. This exposes "
                        "GPU resources and model data to unauthorized access."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM05"],
                    owasp_agentic=["ASI04"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Exposed infra at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add authentication to training endpoints. Use Jupyter "
                        "password/token auth. Bind to 127.0.0.1 and use SSH "
                        "tunnels or VPN for remote access."
                    ),
                    cvss_score=7.5,
                    ai_risk_score=7.0,
                )

    def _check_unprotected_artifacts(self, files: dict[str, str]) -> None:
        """Check for artifact uploads without retention policies."""
        for fpath, content in files.items():
            artifact_matches = list(ARTIFACT_UPLOAD_PATTERNS.finditer(content))
            if not artifact_matches:
                continue

            has_protection = bool(ARTIFACT_PROTECTION_PATTERNS.search(content))
            if not has_protection:
                lines = [str(content[:m.start()].count("\n") + 1) for m in artifact_matches]
                self.add_finding(
                    title="Unprotected model artifacts in CI",
                    description=(
                        f"Artifact upload at {fpath} (lines: {', '.join(lines)}) "
                        "without retention-days or expiration policy. Model artifacts "
                        "stored indefinitely increase the attack surface and may "
                        "contain sensitive training data."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM05"],
                    owasp_agentic=["ASI04"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unprotected artifacts at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Set retention-days on artifact uploads: "
                        "uses: actions/upload-artifact with retention-days: 7. "
                        "Encrypt sensitive artifacts before upload."
                    ),
                    cvss_score=5.0,
                    ai_risk_score=5.0,
                )

    def _check_no_vuln_scanning(self, combined: str) -> None:
        """Check for missing vulnerability scanning in the pipeline."""
        has_vuln_scan = bool(VULN_SCAN_PATTERNS.search(combined))

        if not has_vuln_scan:
            self.add_finding(
                title="No vulnerability scanning in CI/CD pipeline",
                description=(
                    "CI/CD pipeline does not include vulnerability scanning tools "
                    "(aisec, Trivy, Semgrep, Bandit, Safety, Snyk). Without "
                    "automated security scanning, vulnerabilities in dependencies "
                    "and code are not detected before deployment."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MEASURE"],
                remediation=(
                    "Add security scanning to CI: aisec for AI-specific risks, "
                    "Trivy for container vulnerabilities, Semgrep/Bandit for code "
                    "analysis, and pip-audit/safety for dependency scanning."
                ),
                cvss_score=5.0,
                ai_risk_score=5.0,
            )

    def _check_docker_privileged(self, files: dict[str, str]) -> None:
        """Check for Docker --privileged flag in CI configs."""
        for fpath, content in files.items():
            priv_matches = list(DOCKER_PRIVILEGED_PATTERNS.finditer(content))
            if not priv_matches:
                continue

            lines = [str(content[:m.start()].count("\n") + 1) for m in priv_matches]
            self.add_finding(
                title="Docker --privileged in CI pipeline",
                description=(
                    f"Docker privileged mode at {fpath} (lines: {', '.join(lines)}). "
                    "Privileged containers in CI can escape isolation, access host "
                    "resources, and compromise the entire CI infrastructure."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary=f"Privileged Docker in CI at {fpath}",
                    raw_data=f"Lines: {', '.join(lines)}",
                    location=fpath,
                )],
                remediation=(
                    "Remove --privileged flag from CI Docker runs. Use specific "
                    "--cap-add flags for required capabilities only. Use rootless "
                    "containers or Kaniko for builds."
                ),
                cvss_score=8.0,
                ai_risk_score=7.0,
            )

    def _check_unversioned_deploy(self, files: dict[str, str], combined: str) -> None:
        """Check for :latest tag in model deployments."""
        for fpath, content in files.items():
            latest_matches = list(LATEST_TAG_PATTERNS.finditer(content))
            if not latest_matches:
                continue

            has_versioned = bool(VERSIONED_TAG_PATTERNS.search(content))
            if not has_versioned:
                lines = [str(content[:m.start()].count("\n") + 1) for m in latest_matches]
                self.add_finding(
                    title="Unversioned model deployment using :latest",
                    description=(
                        f"Deployment at {fpath} (lines: {', '.join(lines)}) uses "
                        "the :latest tag for model images. Unversioned deployments "
                        "make rollbacks impossible and prevent auditing which model "
                        "version is in production."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM05"],
                    owasp_agentic=["ASI04"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unversioned :latest deploy at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use specific version tags or SHA digests: "
                        "image: model-server:v1.2.3 or image: model@sha256:abc123. "
                        "Never use :latest in production deployments."
                    ),
                    cvss_score=5.0,
                    ai_risk_score=5.0,
                )

    def _check_missing_branch_protection(self, files: dict[str, str], combined: str) -> None:
        """Check for deploy steps without branch conditions."""
        has_deploy = bool(DEPLOY_STEP_PATTERNS.search(combined))
        has_branch_protection = bool(BRANCH_PROTECTION_PATTERNS.search(combined))

        if has_deploy and not has_branch_protection:
            self.add_finding(
                title="Missing CI branch protections for deployment",
                description=(
                    "Deploy steps in the CI pipeline lack branch conditions. "
                    "Without branch protection, any branch push could trigger "
                    "a production deployment, enabling attackers to deploy "
                    "compromised models via feature branches."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Restrict deploy jobs to protected branches: "
                    "if: github.ref == 'refs/heads/main'. Require PR reviews "
                    "and status checks before merging to deploy branches."
                ),
                cvss_score=6.0,
                ai_risk_score=6.0,
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect CI/CD config files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find / -maxdepth 6 -type f "
            "\\( -name '*.yml' -o -name '*.yaml' -o -name 'Jenkinsfile' "
            "-o -name 'Dockerfile*' -o -name 'Makefile' "
            "-o -name '*.toml' -o -name 'requirements*.txt' "
            "-o -name 'setup.py' -o -name 'setup.cfg' \\) "
            "-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _read_file(self, fpath: str) -> str:
        """Read a file from the container."""
        cid = self.context.container_id
        if not cid:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "head", "-c", "65536", fpath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return ""
            return stdout.decode(errors="replace")
        except Exception:
            return ""
