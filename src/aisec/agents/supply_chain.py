"""Supply chain security analysis agent."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Patterns for dependency files
_DEP_FILES = {
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "requirements_dev.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "pyproject.toml": "pip/poetry",
    "setup.py": "pip",
    "setup.cfg": "pip",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
}

# Patterns indicating an unpinned dependency
UNPINNED_PIP = re.compile(
    r"^([a-zA-Z0-9_-]+)\s*$"  # package name with no version spec
    r"|"
    r"^([a-zA-Z0-9_-]+)\s*>=",  # lower bound only (no upper)
    re.MULTILINE,
)

UNPINNED_NPM = re.compile(
    r'"[^"]+"\s*:\s*"(\*|\^|~|latest|>)',
)


class SupplyChainAgent(BaseAgent):
    """Analyse supply chain risks: image layers, dependencies, secrets, provenance."""

    name: ClassVar[str] = "supply_chain"
    description: ClassVar[str] = (
        "Inspects Docker image layers for CVEs, embedded secrets, "
        "dependency vulnerabilities, unpinned versions, and image provenance."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "ASI04", "ASI05"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run all supply chain checks."""
        await self._check_image_vulnerabilities()
        await self._check_embedded_secrets()
        await self._check_dependency_files()
        await self._check_unpinned_dependencies()
        await self._check_image_provenance()

    # ------------------------------------------------------------------
    # Image vulnerability scanning (Trivy)
    # ------------------------------------------------------------------

    async def _check_image_vulnerabilities(self) -> None:
        """Run Trivy (if available) against the target image."""
        image = self.context.target_image
        if not image:
            logger.debug("No target image specified; skipping CVE scan")
            return

        # Check if trivy is available
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                raise FileNotFoundError
        except (FileNotFoundError, OSError):
            logger.info("Trivy not available; skipping image CVE scan")
            self.add_finding(
                title="Image vulnerability scanner not available",
                description=(
                    "Trivy is not installed or not in PATH. Image layer CVE "
                    "analysis could not be performed. Install Trivy for "
                    "comprehensive supply chain vulnerability detection."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Trivy not found",
                        raw_data="trivy --version returned non-zero or not found",
                    )
                ],
                remediation="Install Trivy: https://aquasecurity.github.io/trivy/",
            )
            return

        # Run Trivy scan
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--timeout", "300s",
                image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=360)
        except asyncio.TimeoutError:
            logger.warning("Trivy scan timed out")
            return
        except Exception as exc:
            logger.warning("Trivy scan failed: %s", exc)
            return

        if proc.returncode != 0:
            logger.warning("Trivy exited with code %d", proc.returncode)
            return

        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("Could not parse Trivy output")
            return

        # Parse results
        results = report.get("Results", [])
        critical_vulns: list[dict] = []
        high_vulns: list[dict] = []
        medium_vulns: list[dict] = []

        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").upper()
                entry = {
                    "id": vuln.get("VulnerabilityID", ""),
                    "pkg": vuln.get("PkgName", ""),
                    "installed": vuln.get("InstalledVersion", ""),
                    "fixed": vuln.get("FixedVersion", ""),
                    "title": vuln.get("Title", ""),
                }
                if sev == "CRITICAL":
                    critical_vulns.append(entry)
                elif sev == "HIGH":
                    high_vulns.append(entry)
                elif sev == "MEDIUM":
                    medium_vulns.append(entry)

        if critical_vulns:
            details = "\n".join(
                f"  {v['id']}: {v['pkg']}@{v['installed']} (fix: {v['fixed'] or 'N/A'})"
                for v in critical_vulns[:20]
            )
            self.add_finding(
                title=f"Critical CVEs in image ({len(critical_vulns)} found)",
                description=(
                    f"Trivy found {len(critical_vulns)} critical vulnerability(ies) "
                    f"in the Docker image '{image}'. Critical vulnerabilities may "
                    "allow remote code execution, privilege escalation, or "
                    "complete system compromise."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04", "ASI05"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(critical_vulns)} critical CVEs",
                        raw_data=details,
                        location=f"image:{image}",
                    )
                ],
                remediation=(
                    "Update the base image and all packages to versions that fix "
                    "these CVEs. Rebuild the container image and redeploy."
                ),
                cvss_score=9.5,
                ai_risk_score=9.0,
            )

        if high_vulns:
            details = "\n".join(
                f"  {v['id']}: {v['pkg']}@{v['installed']} (fix: {v['fixed'] or 'N/A'})"
                for v in high_vulns[:20]
            )
            self.add_finding(
                title=f"High-severity CVEs in image ({len(high_vulns)} found)",
                description=(
                    f"Trivy found {len(high_vulns)} high-severity vulnerability(ies) "
                    f"in the Docker image '{image}'."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(high_vulns)} high CVEs",
                        raw_data=details,
                        location=f"image:{image}",
                    )
                ],
                remediation="Update affected packages to patched versions.",
                cvss_score=7.5,
            )

        if medium_vulns:
            self.add_finding(
                title=f"Medium-severity CVEs in image ({len(medium_vulns)} found)",
                description=(
                    f"Trivy found {len(medium_vulns)} medium-severity vulnerability(ies) "
                    f"in the Docker image '{image}'."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(medium_vulns)} medium CVEs",
                        raw_data="\n".join(
                            f"  {v['id']}: {v['pkg']}" for v in medium_vulns[:15]
                        ),
                        location=f"image:{image}",
                    )
                ],
                remediation="Review and update affected packages during next maintenance window.",
                cvss_score=5.0,
            )

    # ------------------------------------------------------------------
    # Embedded secrets in image layers
    # ------------------------------------------------------------------

    async def _check_embedded_secrets(self) -> None:
        """Check Docker image history for secrets leaked in build layers."""
        image = self.context.target_image
        if not image:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "history", "--no-trunc", "--format",
                "{{.CreatedBy}}", image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            history = stdout.decode(errors="replace")
        except Exception:
            return

        secret_patterns = [
            (re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+"), "password"),
            (re.compile(r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*\S+"), "API key"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
            (re.compile(r"(?i)token\s*[:=]\s*\S{16,}"), "token"),
            (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI key"),
            (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub token"),
        ]

        hits: list[tuple[str, str]] = []
        for line in history.splitlines():
            for pattern, label in secret_patterns:
                if pattern.search(line):
                    # Mask the actual value
                    masked_line = line[:120] + "..." if len(line) > 120 else line
                    hits.append((label, masked_line))

        if hits:
            details = "\n".join(f"  [{label}] {line}" for label, line in hits[:15])
            self.add_finding(
                title=f"Secrets embedded in Docker image layers ({len(hits)} found)",
                description=(
                    f"Found {len(hits)} potential secret(s) in Docker image build "
                    "history. Secrets in image layers persist even if deleted in "
                    "later layers and can be extracted by anyone with access to "
                    "the image."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04", "ASI05"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"Secrets in image layers",
                        raw_data=details,
                        location=f"image:{image}",
                    )
                ],
                remediation=(
                    "Never embed secrets in Dockerfiles or build arguments. Use "
                    "multi-stage builds, Docker secrets, or runtime environment "
                    "injection. Rebuild the image from scratch after removing "
                    "secrets. Rotate all exposed credentials immediately."
                ),
                cvss_score=9.0,
                ai_risk_score=8.5,
            )

    # ------------------------------------------------------------------
    # Dependency file analysis
    # ------------------------------------------------------------------

    async def _check_dependency_files(self) -> None:
        """Locate and analyse dependency files for known issues."""
        cid = self.context.container_id
        if not cid:
            return

        # Find dependency files
        dep_names = " -o ".join(f"-name '{name}'" for name in _DEP_FILES)
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                f"find / -maxdepth 6 -type f \\( {dep_names} \\) 2>/dev/null | head -30",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            found_files = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return

        if not found_files:
            return

        # Store for use by unpinned dependency check
        self.context.metadata["dependency_files"] = {}

        for fpath in found_files:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "cat", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    content = stdout.decode(errors="replace")
                    fname = fpath.rsplit("/", 1)[-1]
                    self.context.metadata["dependency_files"][fpath] = {
                        "content": content,
                        "manager": _DEP_FILES.get(fname, "unknown"),
                    }
            except Exception:
                continue

        dep_count = len(self.context.metadata["dependency_files"])
        if dep_count > 0:
            self.add_finding(
                title=f"Dependency files found ({dep_count} files)",
                description=(
                    f"Found {dep_count} dependency file(s) in the container. "
                    "These have been catalogued for further analysis."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{dep_count} dependency files",
                        raw_data="\n".join(
                            f"  {p} ({d['manager']})"
                            for p, d in self.context.metadata["dependency_files"].items()
                        ),
                        location=f"container:{cid}",
                    )
                ],
                remediation="Review dependencies regularly and keep them up to date.",
            )

    # ------------------------------------------------------------------
    # Unpinned dependencies
    # ------------------------------------------------------------------

    async def _check_unpinned_dependencies(self) -> None:
        """Check for unpinned or loosely-pinned dependencies."""
        dep_files = self.context.metadata.get("dependency_files", {})
        if not dep_files:
            return

        unpinned: list[tuple[str, str, list[str]]] = []  # (file, manager, packages)

        for fpath, info in dep_files.items():
            content = info["content"]
            manager = info["manager"]

            if manager == "pip" and fpath.endswith("requirements.txt"):
                matches = UNPINNED_PIP.findall(content)
                pkgs = [m[0] or m[1] for m in matches if m[0] or m[1]]
                # Filter out comments and empty lines
                pkgs = [p for p in pkgs if p and not p.startswith("#") and not p.startswith("-")]
                if pkgs:
                    unpinned.append((fpath, manager, pkgs))

            elif manager in ("npm", "yarn", "pnpm") and "package.json" in fpath:
                try:
                    pkg_data = json.loads(content)
                    for dep_section in ("dependencies", "devDependencies"):
                        deps = pkg_data.get(dep_section, {})
                        loose = [
                            f"{name}@{ver}"
                            for name, ver in deps.items()
                            if ver in ("*", "latest") or ver.startswith("^") or ver.startswith("~")
                        ]
                        if loose:
                            unpinned.append((fpath, manager, loose))
                except json.JSONDecodeError:
                    pass

        if not unpinned:
            return

        total_pkgs = sum(len(pkgs) for _, _, pkgs in unpinned)
        details = []
        for fpath, manager, pkgs in unpinned:
            details.append(f"  {fpath} ({manager}): {', '.join(pkgs[:10])}")

        self.add_finding(
            title=f"Unpinned dependencies detected ({total_pkgs} packages)",
            description=(
                f"Found {total_pkgs} unpinned or loosely-pinned dependency(ies) "
                f"across {len(unpinned)} file(s). Unpinned dependencies allow "
                "automatic installation of newer versions that may contain "
                "vulnerabilities or malicious code (dependency confusion / "
                "supply chain attacks)."
            ),
            severity=Severity.MEDIUM,
            owasp_llm=["LLM03"],
            owasp_agentic=["ASI04", "ASI05"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"{total_pkgs} unpinned dependencies",
                    raw_data="\n".join(details),
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Pin all dependencies to exact versions (e.g., package==1.2.3 "
                "for pip, \"package\": \"1.2.3\" for npm). Use lock files "
                "(requirements.txt with hashes, package-lock.json, Pipfile.lock) "
                "to ensure reproducible builds. Regularly audit and update "
                "dependencies using tools like pip-audit, npm audit, or Dependabot."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=5.5,
            ai_risk_score=6.0,
        )

    # ------------------------------------------------------------------
    # Image provenance
    # ------------------------------------------------------------------

    async def _check_image_provenance(self) -> None:
        """Check image provenance: base image, labels, signatures."""
        image = self.context.target_image
        if not image:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "--format", "{{json .Config}}", image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            config = json.loads(stdout.decode(errors="replace"))
        except Exception:
            return

        labels = config.get("Labels") or {}
        issues: list[str] = []

        # Check for standard provenance labels
        provenance_labels = [
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.created",
            "org.opencontainers.image.authors",
            "org.opencontainers.image.vendor",
            "org.opencontainers.image.version",
        ]
        missing_labels = [l for l in provenance_labels if l not in labels]
        if missing_labels:
            issues.append(
                f"Missing OCI provenance labels: {', '.join(missing_labels)}"
            )

        # Check if image uses latest tag (anti-pattern)
        if image.endswith(":latest") or ":" not in image.split("/")[-1]:
            issues.append(
                "Image uses 'latest' tag or no tag, making builds non-reproducible"
            )

        # Check for image signing (cosign / Docker Content Trust)
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "trust", "inspect", "--pretty", image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            trust_info = stdout.decode(errors="replace") if proc.returncode == 0 else ""
            if not trust_info or "No signatures" in trust_info:
                issues.append("Image is not signed (Docker Content Trust / cosign)")
        except Exception:
            issues.append("Could not verify image signature")

        if issues:
            self.add_finding(
                title=f"Image provenance issues ({len(issues)} found)",
                description=(
                    f"The Docker image '{image}' has {len(issues)} provenance "
                    "issue(s). Weak provenance makes it difficult to verify the "
                    "image's origin, integrity, and build reproducibility."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Image provenance issues",
                        raw_data="\n".join(f"  - {i}" for i in issues),
                        location=f"image:{image}",
                    )
                ],
                remediation=(
                    "Add OCI standard labels to the Dockerfile. Use specific image "
                    "tags with digests (e.g., image@sha256:...) instead of 'latest'. "
                    "Sign images using cosign or Docker Content Trust. Implement "
                    "a supply chain security framework (e.g., SLSA)."
                ),
                references=[
                    "https://slsa.dev/",
                    "https://github.com/sigstore/cosign",
                ],
                cvss_score=4.0,
                ai_risk_score=5.0,
            )
