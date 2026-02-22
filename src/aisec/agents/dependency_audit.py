"""Dependency audit agent for vulnerability and supply chain analysis."""

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

# Popular AI/ML packages for typosquatting detection
POPULAR_AI_PACKAGES = [
    "transformers", "torch", "tensorflow", "langchain", "openai",
    "anthropic", "huggingface-hub", "sentence-transformers", "safetensors",
    "tokenizers", "pydantic", "fastapi", "flask", "numpy", "pandas",
    "scikit-learn", "keras", "pytorch-lightning", "diffusers", "accelerate",
    "datasets", "gradio", "streamlit", "llama-index", "chromadb",
    "pinecone-client", "weaviate-client", "qdrant-client",
]

# Known malicious package names (subset of commonly reported)
KNOWN_MALICIOUS_PACKAGES = {
    "python-openai", "openai-python", "chatgpt-python", "gpt4-python",
    "pytorch-nightly-gpu", "tf-nightly-gpu", "nvidiacuda",
    "python-binance-api", "discordpy-self", "discord-selfbot",
    "colorama-dev", "pip-install", "python-pip", "setup-tools",
    "urllib4", "urlib3", "requessts", "beautifulsoup5",
    "python-dateutils", "python-mysql", "python3-dateutil",
    "python-jwt", "pycryptodome-fix", "crypto-utils",
    "ai-toolkit", "ml-pipeline", "torch-utils", "tf-helper",
    "langchain-helper", "openai-utils", "anthropic-sdk",
    "huggingface-utils", "transformers-helper", "llm-utils",
    "agent-toolkit", "auto-gpt-plugin", "chatbot-helper",
    "prompt-toolkit-extra", "llm-guard-bypass",
    "model-download", "weights-download", "ggml-python",
    "ctransformers-gpu", "bitsandbytes-cuda", "flash-attn-cuda",
}

# Dependency file patterns
DEP_FILE_PATTERNS = [
    "requirements.txt", "requirements*.txt",
    "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock",
    "poetry.lock", "pdm.lock",
    "package.json", "package-lock.json", "yarn.lock",
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


class DependencyAuditAgent(BaseAgent):
    """Audit dependencies for vulnerabilities, typosquatting, and staleness."""

    name: ClassVar[str] = "dependency_audit"
    description: ClassVar[str] = (
        "Audits project dependencies using pip-audit for known vulnerabilities, "
        "checks for typosquatting attacks against popular AI packages, and "
        "flags known malicious packages."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "ASI04"]
    depends_on: ClassVar[list[str]] = ["supply_chain"]

    async def analyze(self) -> None:
        """Run dependency audit checks."""
        dep_files = await self._find_dependency_files()
        if not dep_files:
            self.add_finding(
                title="No dependency files found",
                description=(
                    "No dependency specification files (requirements.txt, "
                    "pyproject.toml, etc.) were found in the container."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
            )
            return

        pip_audit_ran = await self._run_pip_audit()

        # Parse dependency files for additional checks
        packages = await self._parse_dependencies(dep_files)

        if packages:
            await self._check_typosquatting(packages)
            await self._check_malicious_packages(packages)
            await self._check_pinning(packages, dep_files)

        if not pip_audit_ran:
            self.add_finding(
                title="pip-audit not available for vulnerability scanning",
                description=(
                    "pip-audit is not installed. Dependency vulnerability "
                    "scanning was limited to package name analysis. Install "
                    "pip-audit for CVE-level vulnerability detection."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                remediation="pip install pip-audit",
            )

    async def _find_dependency_files(self) -> list[str]:
        """Find dependency specification files in the container."""
        cid = self.context.container_id
        if not cid:
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "find /app /src /opt -maxdepth 4 -type f "
                "\\( -name 'requirements*.txt' -o -name 'pyproject.toml' "
                "-o -name 'setup.py' -o -name 'setup.cfg' "
                "-o -name 'Pipfile' -o -name 'Pipfile.lock' "
                "-o -name 'poetry.lock' -o -name 'package.json' "
                "-o -name 'yarn.lock' \\) 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _run_pip_audit(self) -> bool:
        """Run pip-audit for known vulnerability detection."""
        cid = self.context.container_id
        if not cid:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "pip-audit", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                # Try on host
                proc = await asyncio.create_subprocess_exec(
                    "pip-audit", "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                if proc.returncode != 0:
                    return False
        except (FileNotFoundError, OSError):
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "pip-audit", "--format=json", "--desc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="replace")

            if not output.strip():
                return True

            data = json.loads(output)
            dependencies = data.get("dependencies", [])

            for dep in dependencies:
                vulns = dep.get("vulns", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    desc = vuln.get("description", "")
                    fix_version = vuln.get("fix_versions", [])
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")

                    # Determine severity from CVSS or vuln ID
                    if "CRITICAL" in desc.upper() or vuln.get("cvss", 0) >= 9.0:
                        sev = Severity.CRITICAL
                    elif vuln.get("cvss", 0) >= 7.0:
                        sev = Severity.HIGH
                    elif vuln.get("cvss", 0) >= 4.0:
                        sev = Severity.MEDIUM
                    else:
                        sev = Severity.LOW

                    fix_str = f" Fix available: {', '.join(fix_version)}" if fix_version else ""

                    self.add_finding(
                        title=f"Vulnerable dependency: {pkg_name}=={pkg_version} ({vuln_id})",
                        description=(
                            f"Package {pkg_name} version {pkg_version} has known "
                            f"vulnerability {vuln_id}. {desc[:300]}{fix_str}"
                        ),
                        severity=sev,
                        owasp_llm=["LLM03"],
                        owasp_agentic=["ASI04"],
                        nist_ai_rmf=["GOVERN", "MANAGE"],
                        evidence=[
                            Evidence(
                                type="config",
                                summary=f"{vuln_id}: {pkg_name}=={pkg_version}",
                                raw_data=json.dumps(vuln, indent=2)[:500],
                                location=f"pip:{pkg_name}",
                            )
                        ],
                        remediation=(
                            f"Upgrade {pkg_name} to version "
                            f"{', '.join(fix_version) if fix_version else 'latest'}."
                        ),
                        references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                        cvss_score=vuln.get("cvss"),
                    )

            return True
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("pip-audit execution failed: %s", exc)
            return True

    async def _parse_dependencies(
        self, dep_files: list[str],
    ) -> list[tuple[str, str]]:
        """Parse dependency files to extract (package, version) pairs."""
        cid = self.context.container_id
        if not cid:
            return []

        packages: list[tuple[str, str]] = []

        for fpath in dep_files:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "32768", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    continue
                content = stdout.decode(errors="replace")
            except Exception:
                continue

            if fpath.endswith("requirements.txt") or "requirements" in fpath:
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;#]+)", line)
                    if match:
                        packages.append((match.group(1).lower(), match.group(2)))
                    elif re.match(r"^[a-zA-Z0-9_.-]+$", line):
                        packages.append((line.lower(), "unpinned"))

            elif fpath.endswith("pyproject.toml"):
                for line in content.splitlines():
                    match = re.match(
                        r'\s*"([a-zA-Z0-9_.-]+)\s*(?:>=|==|~=)\s*([^"]+)"', line
                    )
                    if match:
                        packages.append((match.group(1).lower(), match.group(2)))

        return packages

    async def _check_typosquatting(
        self, packages: list[tuple[str, str]],
    ) -> None:
        """Check for potential typosquatting attacks."""
        suspects: list[tuple[str, str, int]] = []

        for pkg_name, _ in packages:
            normalized = pkg_name.replace("-", "").replace("_", "").lower()
            for popular in POPULAR_AI_PACKAGES:
                popular_normalized = popular.replace("-", "").replace("_", "").lower()
                if normalized == popular_normalized:
                    continue  # Exact match, not typosquat
                dist = _levenshtein_distance(normalized, popular_normalized)
                if 1 <= dist <= 2 and len(normalized) > 3:
                    suspects.append((pkg_name, popular, dist))

        if suspects:
            details = "\n".join(
                f"  {pkg} (similar to {popular}, distance={dist})"
                for pkg, popular, dist in suspects
            )
            self.add_finding(
                title=f"Potential typosquatting packages detected ({len(suspects)})",
                description=(
                    f"Found {len(suspects)} package(s) with names very similar to "
                    "popular AI/ML packages. These could be typosquatting attacks "
                    "designed to install malicious code."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Typosquatting candidates",
                        raw_data=details,
                        location="dependency files",
                    )
                ],
                remediation=(
                    "Verify the correct package names. Use pip install with "
                    "--require-hashes for integrity verification."
                ),
                cvss_score=8.0,
                ai_risk_score=9.0,
            )

    async def _check_malicious_packages(
        self, packages: list[tuple[str, str]],
    ) -> None:
        """Check against known malicious package list."""
        found_malicious: list[str] = []

        for pkg_name, version in packages:
            if pkg_name.lower() in KNOWN_MALICIOUS_PACKAGES:
                found_malicious.append(f"{pkg_name}=={version}")

        if found_malicious:
            self.add_finding(
                title=f"Known malicious packages detected ({len(found_malicious)})",
                description=(
                    f"Found {len(found_malicious)} package(s) matching known "
                    f"malicious package names: {', '.join(found_malicious[:10])}. "
                    "These packages are known to contain malware, backdoors, or "
                    "credential stealers."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Malicious packages",
                        raw_data="\n".join(found_malicious),
                        location="dependency files",
                    )
                ],
                remediation=(
                    "IMMEDIATELY remove these packages. Audit the system for "
                    "compromise. Rotate all credentials that may have been exposed."
                ),
                cvss_score=10.0,
                ai_risk_score=10.0,
            )

    async def _check_pinning(
        self,
        packages: list[tuple[str, str]],
        dep_files: list[str],
    ) -> None:
        """Check for unpinned or loosely pinned dependencies."""
        unpinned = [pkg for pkg, ver in packages if ver == "unpinned"]

        if len(unpinned) > 3:
            self.add_finding(
                title=f"Unpinned dependencies ({len(unpinned)} packages)",
                description=(
                    f"Found {len(unpinned)} unpinned dependencies: "
                    f"{', '.join(unpinned[:10])}{'...' if len(unpinned) > 10 else ''}. "
                    "Unpinned dependencies may introduce breaking changes or "
                    "supply chain attacks through compromised versions."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(unpinned)} unpinned packages",
                        raw_data="\n".join(unpinned[:20]),
                        location=", ".join(dep_files[:3]),
                    )
                ],
                remediation=(
                    "Pin all dependencies to exact versions using ==. Use "
                    "pip-compile or pip freeze to generate a locked requirements file."
                ),
                cvss_score=4.0,
            )
