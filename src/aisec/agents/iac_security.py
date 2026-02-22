"""Infrastructure as Code security agent for Dockerfile and K8s manifest scanning."""

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

# Built-in Dockerfile security checks
DOCKERFILE_CHECKS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "Running as root (no USER directive)",
        re.compile(r"^(?!.*\bUSER\b).*$", re.DOTALL),
        Severity.HIGH,
        "No USER directive found. The container will run as root by default, "
        "increasing the attack surface if the AI agent is compromised.",
        "Add 'USER nonroot' or 'USER 1000:1000' to the Dockerfile.",
    ),
    (
        "Using :latest base image",
        re.compile(r"FROM\s+\S+:latest\b", re.IGNORECASE),
        Severity.MEDIUM,
        "Using :latest tag for base image makes builds non-reproducible and "
        "may pull in vulnerable versions.",
        "Pin base images to specific digest or version tags.",
    ),
    (
        "ADD instruction (URL injection risk)",
        re.compile(r"^ADD\s+https?://", re.MULTILINE | re.IGNORECASE),
        Severity.MEDIUM,
        "ADD with URLs can download content that may be tampered with. "
        "COPY is safer for local files.",
        "Use COPY for local files. For remote files, use RUN curl/wget with "
        "checksum verification.",
    ),
    (
        "Secrets in ENV or ARG",
        re.compile(
            r"(?:ENV|ARG)\s+(?:\S*(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY)\S*)\s*=",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Secrets exposed in ENV/ARG are visible in image layers and docker inspect.",
        "Use Docker secrets, build-time secrets (--secret), or runtime "
        "environment variables instead of baking secrets into the image.",
    ),
    (
        "No HEALTHCHECK instruction",
        re.compile(r"^(?!.*\bHEALTHCHECK\b).*$", re.DOTALL),
        Severity.LOW,
        "No HEALTHCHECK defined. Container orchestrators cannot detect unhealthy "
        "AI agent instances.",
        "Add HEALTHCHECK instruction to monitor container health.",
    ),
    (
        "Missing --no-cache-dir on pip install",
        re.compile(r"pip\s+install(?!.*--no-cache-dir)", re.IGNORECASE),
        Severity.LOW,
        "pip install without --no-cache-dir leaves cached packages in the "
        "image, increasing image size and potential attack surface.",
        "Add --no-cache-dir to pip install commands.",
    ),
    (
        "Exposed sensitive ports",
        re.compile(r"EXPOSE\s+(?:22|3306|5432|6379|27017|9200)\b"),
        Severity.MEDIUM,
        "Exposing management/database ports (SSH, MySQL, PostgreSQL, Redis, "
        "MongoDB, Elasticsearch) increases the attack surface.",
        "Only expose necessary application ports. Database access should be "
        "through internal container networks.",
    ),
    (
        "shell=True in RUN commands",
        re.compile(r"RUN.*shell\s*=\s*True", re.IGNORECASE),
        Severity.MEDIUM,
        "Using shell=True in RUN commands can lead to shell injection if "
        "build args are interpolated.",
        "Use exec form RUN [\"cmd\", \"arg\"] instead of shell form.",
    ),
    (
        "COPY or ADD with wildcard",
        re.compile(r"(?:COPY|ADD)\s+\.\s+", re.IGNORECASE),
        Severity.LOW,
        "COPY . or ADD . copies the entire build context, potentially "
        "including .env files, secrets, and .git directory.",
        "Use .dockerignore and copy only necessary files.",
    ),
]

# Built-in K8s manifest security checks
K8S_CHECKS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "Privileged container",
        re.compile(r"privileged:\s*true", re.IGNORECASE),
        Severity.CRITICAL,
        "Container running in privileged mode has full access to the host.",
        "Remove privileged: true. Use specific capabilities if needed.",
    ),
    (
        "Host network enabled",
        re.compile(r"hostNetwork:\s*true", re.IGNORECASE),
        Severity.HIGH,
        "Container shares the host network namespace, bypassing network "
        "isolation and potentially exposing host services.",
        "Remove hostNetwork: true. Use Kubernetes services for networking.",
    ),
    (
        "Running as root",
        re.compile(r"runAsUser:\s*0\b"),
        Severity.HIGH,
        "Pod is explicitly configured to run as root (UID 0).",
        "Set runAsUser to a non-root UID. Add runAsNonRoot: true.",
    ),
    (
        "Missing resource limits",
        re.compile(r"containers:(?!.*limits:).*$", re.DOTALL),
        Severity.MEDIUM,
        "No resource limits set. AI workloads without limits can consume "
        "all node resources, affecting other workloads.",
        "Set CPU and memory limits for all containers.",
    ),
    (
        "Host PID namespace",
        re.compile(r"hostPID:\s*true", re.IGNORECASE),
        Severity.HIGH,
        "Container shares the host PID namespace, allowing process inspection.",
        "Remove hostPID: true.",
    ),
    (
        "Writable root filesystem",
        re.compile(r"readOnlyRootFilesystem:\s*false", re.IGNORECASE),
        Severity.MEDIUM,
        "Root filesystem is writable, allowing potential persistence.",
        "Set readOnlyRootFilesystem: true and use volumes for writable paths.",
    ),
    (
        "Missing securityContext",
        re.compile(r"containers:(?!.*securityContext:).*$", re.DOTALL),
        Severity.MEDIUM,
        "No securityContext defined for the container.",
        "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, "
        "and allowPrivilegeEscalation: false.",
    ),
]


class IaCSecurityAgent(BaseAgent):
    """Scan Dockerfiles and Kubernetes manifests for security issues."""

    name: ClassVar[str] = "iac_security"
    description: ClassVar[str] = (
        "Scans Infrastructure as Code files (Dockerfiles, docker-compose, "
        "Kubernetes manifests, Helm charts) using Checkov and built-in "
        "security checks for misconfigurations."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "LLM06", "ASI03", "ASI04"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run IaC security checks."""
        dockerfile_content = await self._extract_dockerfile()
        k8s_manifests = await self._find_k8s_manifests()
        compose_files = await self._find_compose_files()

        if not dockerfile_content and not k8s_manifests and not compose_files:
            self.add_finding(
                title="No IaC files found for analysis",
                description=(
                    "No Dockerfiles, Kubernetes manifests, or docker-compose "
                    "files were found."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
            )
            return

        checkov_ran = await self._run_checkov(dockerfile_content, k8s_manifests)

        if dockerfile_content:
            await self._check_dockerfile(dockerfile_content)

        for manifest_path, manifest_content in k8s_manifests:
            await self._check_k8s_manifest(manifest_path, manifest_content)

        if not checkov_ran:
            self.add_finding(
                title="Checkov not available for IaC scanning",
                description=(
                    "Checkov is not installed. Only built-in checks were "
                    "performed. Install checkov for comprehensive IaC security "
                    "scanning with CIS benchmark coverage."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
                remediation="pip install checkov",
            )

    async def _extract_dockerfile(self) -> str:
        """Extract Dockerfile content from image history or container."""
        cid = self.context.container_id
        if not cid:
            return ""

        # Try to find Dockerfile in the container
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "find / -maxdepth 4 -name 'Dockerfile*' -type f 2>/dev/null | head -5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                files = stdout.decode(errors="replace").strip().splitlines()
                for f in files:
                    f = f.strip()
                    if not f:
                        continue
                    proc = await asyncio.create_subprocess_exec(
                        "docker", "exec", cid, "head", "-c", "32768", f,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    if proc.returncode == 0:
                        content = stdout.decode(errors="replace")
                        if "FROM" in content.upper():
                            return content
        except Exception:
            pass

        # Fallback: reconstruct from docker history
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "history", "--no-trunc",
                "--format", "{{.CreatedBy}}", self.context.target_image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                return stdout.decode(errors="replace")
        except Exception:
            pass

        return ""

    async def _find_k8s_manifests(self) -> list[tuple[str, str]]:
        """Find Kubernetes manifest files in the container."""
        cid = self.context.container_id
        if not cid:
            return []

        manifests: list[tuple[str, str]] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "find / -maxdepth 5 -type f -name '*.yaml' -o -name '*.yml' "
                "2>/dev/null | xargs grep -l 'apiVersion\\|kind:.*Deployment\\|"
                "kind:.*Pod\\|kind:.*Service' 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []

            for fpath in stdout.decode(errors="replace").strip().splitlines():
                fpath = fpath.strip()
                if not fpath:
                    continue
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "32768", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    manifests.append((fpath, stdout.decode(errors="replace")))
        except Exception:
            pass

        return manifests

    async def _find_compose_files(self) -> list[tuple[str, str]]:
        """Find docker-compose files in the container."""
        cid = self.context.container_id
        if not cid:
            return []

        files: list[tuple[str, str]] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "find / -maxdepth 4 -type f "
                "\\( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \\) "
                "2>/dev/null | head -10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                for fpath in stdout.decode(errors="replace").strip().splitlines():
                    fpath = fpath.strip()
                    if not fpath:
                        continue
                    proc = await asyncio.create_subprocess_exec(
                        "docker", "exec", cid, "head", "-c", "32768", fpath,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    if proc.returncode == 0:
                        files.append((fpath, stdout.decode(errors="replace")))
        except Exception:
            pass

        return files

    async def _run_checkov(
        self,
        dockerfile_content: str,
        k8s_manifests: list[tuple[str, str]],
    ) -> bool:
        """Run Checkov on IaC files."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "checkov", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False
        except (FileNotFoundError, OSError):
            return False

        # Write content to temp files and run checkov
        import tempfile
        import os

        checks_found = False

        if dockerfile_content and "FROM" in dockerfile_content.upper():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix="Dockerfile", delete=False,
            ) as tmp:
                tmp.write(dockerfile_content)
                tmp_path = tmp.name

            try:
                proc = await asyncio.create_subprocess_exec(
                    "checkov", "-f", tmp_path, "-o", "json", "--compact",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode(errors="replace")
                if output.strip():
                    await self._parse_checkov_results(output, "Dockerfile")
                    checks_found = True
            except Exception as exc:
                logger.warning("Checkov Dockerfile scan failed: %s", exc)
            finally:
                os.unlink(tmp_path)

        for manifest_path, manifest_content in k8s_manifests[:5]:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False,
            ) as tmp:
                tmp.write(manifest_content)
                tmp_path = tmp.name

            try:
                proc = await asyncio.create_subprocess_exec(
                    "checkov", "-f", tmp_path, "-o", "json", "--compact",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode(errors="replace")
                if output.strip():
                    await self._parse_checkov_results(output, manifest_path)
                    checks_found = True
            except Exception as exc:
                logger.warning("Checkov K8s scan failed: %s", exc)
            finally:
                os.unlink(tmp_path)

        return checks_found

    async def _parse_checkov_results(self, output: str, source: str) -> None:
        """Parse Checkov JSON output and create findings."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return

        # Checkov can return a list or a dict
        results_list = data if isinstance(data, list) else [data]

        for result_block in results_list:
            failed_checks = result_block.get("results", {}).get("failed_checks", [])
            for check in failed_checks:
                check_id = check.get("check_id", "")
                check_name = check.get("name", "Unknown check")
                guideline = check.get("guideline", "")

                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                sev = severity_map.get(
                    check.get("severity", "MEDIUM"),
                    Severity.MEDIUM,
                )

                self.add_finding(
                    title=f"Checkov {check_id}: {check_name}",
                    description=f"Checkov IaC check failed: {check_name}",
                    severity=sev,
                    owasp_llm=["LLM06"],
                    owasp_agentic=["ASI03", "ASI04"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary=f"Checkov {check_id}",
                            raw_data=json.dumps(check, indent=2)[:500],
                            location=source,
                        )
                    ],
                    remediation=guideline or f"Fix {check_id} per CIS benchmark.",
                    references=[guideline] if guideline else [],
                )

    async def _check_dockerfile(self, content: str) -> None:
        """Run built-in Dockerfile security checks."""
        for check_name, pattern, severity, description, remediation in DOCKERFILE_CHECKS:
            # Special handling for "absence" checks
            if check_name in (
                "Running as root (no USER directive)",
                "No HEALTHCHECK instruction",
            ):
                if not re.search(
                    r"\bUSER\b" if "USER" in check_name else r"\bHEALTHCHECK\b",
                    content,
                    re.IGNORECASE,
                ):
                    self.add_finding(
                        title=f"Dockerfile: {check_name}",
                        description=description,
                        severity=severity,
                        owasp_llm=["LLM06"],
                        owasp_agentic=["ASI03"],
                        nist_ai_rmf=["GOVERN"],
                        evidence=[
                            Evidence(
                                type="config",
                                summary=check_name,
                                raw_data=content[:300],
                                location="Dockerfile",
                            )
                        ],
                        remediation=remediation,
                        cvss_score=7.0 if severity == Severity.HIGH else 4.0,
                    )
            else:
                matches = list(pattern.finditer(content))
                if matches:
                    snippets = [
                        content[max(0, m.start() - 20):min(len(content), m.end() + 40)].strip()
                        for m in matches[:5]
                    ]
                    self.add_finding(
                        title=f"Dockerfile: {check_name} ({len(matches)} instances)",
                        description=description,
                        severity=severity,
                        owasp_llm=["LLM06"],
                        owasp_agentic=["ASI03", "ASI04"],
                        nist_ai_rmf=["GOVERN"],
                        evidence=[
                            Evidence(
                                type="config",
                                summary=check_name,
                                raw_data="\n".join(snippets),
                                location="Dockerfile",
                            )
                        ],
                        remediation=remediation,
                        cvss_score=7.0 if severity == Severity.HIGH else 4.0,
                    )

    async def _check_k8s_manifest(self, path: str, content: str) -> None:
        """Run built-in Kubernetes manifest security checks."""
        for check_name, pattern, severity, description, remediation in K8S_CHECKS:
            # Special handling for "absence" checks
            if check_name in ("Missing resource limits", "Missing securityContext"):
                keyword = "limits:" if "limits" in check_name else "securityContext:"
                if "containers:" in content and keyword not in content:
                    self.add_finding(
                        title=f"K8s: {check_name} in {path}",
                        description=description,
                        severity=severity,
                        owasp_llm=["LLM06"],
                        owasp_agentic=["ASI03"],
                        nist_ai_rmf=["GOVERN"],
                        evidence=[
                            Evidence(
                                type="config",
                                summary=check_name,
                                raw_data=content[:300],
                                location=path,
                            )
                        ],
                        remediation=remediation,
                    )
            else:
                matches = list(pattern.finditer(content))
                if matches:
                    self.add_finding(
                        title=f"K8s: {check_name} in {path}",
                        description=description,
                        severity=severity,
                        owasp_llm=["LLM06"],
                        owasp_agentic=["ASI03"],
                        nist_ai_rmf=["GOVERN"],
                        evidence=[
                            Evidence(
                                type="config",
                                summary=check_name,
                                raw_data=content[:300],
                                location=path,
                            )
                        ],
                        remediation=remediation,
                        cvss_score=9.0 if severity == Severity.CRITICAL else 7.0,
                    )
