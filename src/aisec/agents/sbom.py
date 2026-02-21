"""SBOM (Software Bill of Materials) security analysis agent.

Performs deep supply chain analysis including SBOM detection, dependency
enumeration, license compliance, transitive dependency depth analysis,
unpinned version detection, CVE cross-referencing, and CycloneDX SBOM
generation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, ClassVar
from uuid import uuid4

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence
from aisec.utils.parsers import Dependency, parse_package_json, parse_requirements_txt

logger = logging.getLogger(__name__)

# Dependency manifest files to search for inside containers.
_MANIFEST_FILES: dict[str, str] = {
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "poetry",
    "package.json": "npm",
    "package-lock.json": "npm",
    "go.sum": "go",
    "go.mod": "go",
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "Gemfile.lock": "bundler",
    "Gemfile": "bundler",
}

# SBOM format file patterns.
_SBOM_PATTERNS: list[tuple[str, str]] = [
    ("bom.json", "CycloneDX"),
    ("sbom.json", "CycloneDX"),
    ("cyclonedx.json", "CycloneDX"),
    ("sbom.xml", "CycloneDX"),
    ("bom.xml", "CycloneDX"),
    ("cyclonedx.xml", "CycloneDX"),
    ("*.spdx", "SPDX"),
    ("*.spdx.json", "SPDX"),
    ("*.spdx.rdf", "SPDX"),
    ("*.spdx.xml", "SPDX"),
]

# Licenses considered copyleft / restrictive.
_COPYLEFT_LICENSES: set[str] = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "EUPL-1.2", "MPL-2.0", "SSPL-1.0",
}

# Licenses considered permissive.
_PERMISSIVE_LICENSES: set[str] = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "Unlicense", "0BSD", "CC0-1.0", "Zlib", "BSL-1.0",
}

# Maximum depth threshold for transitive dependency chains.
_MAX_DEPTH_THRESHOLD = 10


class SBOMAgent(BaseAgent):
    """Analyse software bill of materials, dependency health, and license compliance."""

    name: ClassVar[str] = "sbom"
    description: ClassVar[str] = (
        "Detects existing SBOMs, enumerates dependencies from manifest files, "
        "checks license compliance, analyses transitive dependency depth, "
        "flags unpinned versions, cross-references known CVEs, and generates "
        "a minimal CycloneDX SBOM."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "ASI04"]
    depends_on: ClassVar[list[str]] = ["supply_chain"]

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self._dependencies: list[Dependency] = []
        self._manifest_contents: dict[str, str] = {}
        self._detected_licenses: dict[str, str] = {}  # package -> license

    # ------------------------------------------------------------------
    # Main analysis entrypoint
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all SBOM-related checks sequentially."""
        await self._check_sbom_exists()
        await self._enumerate_dependencies()
        await self._check_license_compliance()
        await self._check_dependency_depth()
        await self._check_unpinned_versions()
        await self._check_known_cves()
        await self._generate_sbom()

    # ------------------------------------------------------------------
    # Helpers for container command execution
    # ------------------------------------------------------------------

    async def _exec_in_container(
        self,
        *cmd: str,
        timeout: float = 60.0,
    ) -> tuple[int, str, str]:
        """Execute a command inside the container via ``docker exec``.

        Returns (returncode, stdout, stderr). Returns (-1, "", error_msg)
        if the container is unavailable or the command cannot be run.
        """
        cid = self.context.container_id
        if not cid:
            return -1, "", "No container_id in scan context"

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
            return (
                proc.returncode or 0,
                stdout_bytes.decode(errors="replace"),
                stderr_bytes.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            logger.warning("Container command timed out: %s", " ".join(cmd))
            return -1, "", "Command timed out"
        except (FileNotFoundError, OSError) as exc:
            logger.warning("Cannot execute docker: %s", exc)
            return -1, "", str(exc)

    # ------------------------------------------------------------------
    # 1. SBOM Detection
    # ------------------------------------------------------------------

    async def _check_sbom_exists(self) -> None:
        """Check whether a pre-existing SBOM is shipped inside the container."""
        cid = self.context.container_id
        if not cid:
            logger.debug("No container_id; skipping SBOM detection")
            return

        # Build a find command that searches for common SBOM filenames.
        name_clauses = " -o ".join(
            f"-name '{pattern}'" for pattern, _ in _SBOM_PATTERNS
        )
        find_cmd = (
            f"find / -maxdepth 5 -type f \\( {name_clauses} \\) "
            f"2>/dev/null | head -20"
        )

        rc, stdout, _ = await self._exec_in_container("sh", "-c", find_cmd)
        if rc != 0:
            logger.debug("SBOM search command failed (rc=%d)", rc)

        found_files = [
            line.strip() for line in stdout.splitlines() if line.strip()
        ]

        if found_files:
            formats_found = set()
            for fpath in found_files:
                for pattern, fmt in _SBOM_PATTERNS:
                    # Simple suffix matching (the glob * patterns).
                    suffix = pattern.lstrip("*")
                    if fpath.endswith(suffix):
                        formats_found.add(fmt)
                        break

            self.add_finding(
                title=f"SBOM detected in container ({', '.join(formats_found)})",
                description=(
                    f"Found {len(found_files)} SBOM file(s) in the container "
                    f"filesystem in format(s): {', '.join(formats_found)}. "
                    "Pre-existing SBOMs improve supply chain transparency."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="SBOM files found",
                        raw_data="\n".join(f"  {f}" for f in found_files),
                        location=f"container:{cid}",
                    )
                ],
            )
        else:
            self.add_finding(
                title="No SBOM found in container",
                description=(
                    "No Software Bill of Materials (CycloneDX or SPDX) was "
                    "detected inside the container. An SBOM is essential for "
                    "supply chain transparency, vulnerability management, "
                    "and regulatory compliance."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="SBOM absent",
                        raw_data="No CycloneDX or SPDX files found in container",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Generate and ship an SBOM with your container image. Use "
                    "tools like syft, cdxgen, or trivy to produce CycloneDX or "
                    "SPDX documents at build time. Include the SBOM at a "
                    "well-known path such as /opt/sbom/bom.json."
                ),
                references=[
                    "https://cyclonedx.org/",
                    "https://spdx.dev/",
                    "https://github.com/anchore/syft",
                ],
            )

    # ------------------------------------------------------------------
    # 2. Dependency Enumeration
    # ------------------------------------------------------------------

    async def _enumerate_dependencies(self) -> None:
        """Locate and parse dependency manifests inside the container."""
        cid = self.context.container_id
        if not cid:
            return

        name_clauses = " -o ".join(
            f"-name '{name}'" for name in _MANIFEST_FILES
        )
        find_cmd = (
            f"find / -maxdepth 6 -type f \\( {name_clauses} \\) "
            f"2>/dev/null | head -40"
        )

        rc, stdout, _ = await self._exec_in_container("sh", "-c", find_cmd)
        if rc != 0 and not stdout.strip():
            logger.debug("Dependency file search failed")
            return

        found_paths = [l.strip() for l in stdout.splitlines() if l.strip()]
        if not found_paths:
            return

        for fpath in found_paths:
            rc, content, _ = await self._exec_in_container("cat", fpath)
            if rc != 0 or not content:
                continue

            fname = fpath.rsplit("/", 1)[-1]
            self._manifest_contents[fpath] = content

            if fname in ("requirements.txt", "requirements-dev.txt"):
                self._dependencies.extend(parse_requirements_txt(content))
            elif fname == "package.json":
                self._dependencies.extend(parse_package_json(content))
            elif fname == "Pipfile.lock":
                self._parse_pipfile_lock(content)
            elif fname == "poetry.lock":
                self._parse_poetry_lock(content)
            elif fname == "go.sum":
                self._parse_go_sum(content)
            elif fname == "Cargo.lock":
                self._parse_cargo_lock(content)
            elif fname == "Gemfile.lock":
                self._parse_gemfile_lock(content)

        if self._dependencies:
            dep_summary = (
                f"Enumerated {len(self._dependencies)} dependencies from "
                f"{len(found_paths)} manifest file(s)."
            )
            self.add_finding(
                title=f"Dependencies enumerated ({len(self._dependencies)} packages)",
                description=dep_summary,
                severity=Severity.INFO,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(self._dependencies)} deps from {len(found_paths)} files",
                        raw_data="\n".join(
                            f"  {d.name}=={d.version} (pinned={d.pinned}, src={d.source})"
                            for d in self._dependencies[:50]
                        ),
                        location=f"container:{cid}",
                    )
                ],
            )

    # -- Parsers for additional lockfile formats --

    def _parse_pipfile_lock(self, content: str) -> None:
        """Extract dependencies from Pipfile.lock JSON."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                self._dependencies.append(Dependency(
                    name=name,
                    version=version,
                    pinned=version.startswith("=") or bool(re.match(r"^\d", version)),
                    source="Pipfile.lock",
                ))

    def _parse_poetry_lock(self, content: str) -> None:
        """Extract dependencies from poetry.lock (TOML-like format)."""
        current_name = ""
        current_version = ""
        for line in content.splitlines():
            stripped = line.strip()
            name_match = re.match(r'^name\s*=\s*"(.+)"', stripped)
            ver_match = re.match(r'^version\s*=\s*"(.+)"', stripped)
            if name_match:
                current_name = name_match.group(1)
            elif ver_match:
                current_version = ver_match.group(1)
            elif stripped == "[[package]]" and current_name:
                if current_name and current_version:
                    self._dependencies.append(Dependency(
                        name=current_name,
                        version=current_version,
                        pinned=True,
                        source="poetry.lock",
                    ))
                current_name = ""
                current_version = ""
        # Flush the last package.
        if current_name and current_version:
            self._dependencies.append(Dependency(
                name=current_name,
                version=current_version,
                pinned=True,
                source="poetry.lock",
            ))

    def _parse_go_sum(self, content: str) -> None:
        """Extract modules from go.sum."""
        seen: set[str] = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].split("/")[0].lstrip("v")
                key = f"{module}@{version}"
                if key not in seen:
                    seen.add(key)
                    self._dependencies.append(Dependency(
                        name=module,
                        version=version,
                        pinned=True,
                        source="go.sum",
                    ))

    def _parse_cargo_lock(self, content: str) -> None:
        """Extract crates from Cargo.lock."""
        current_name = ""
        current_version = ""
        for line in content.splitlines():
            stripped = line.strip()
            name_match = re.match(r'^name\s*=\s*"(.+)"', stripped)
            ver_match = re.match(r'^version\s*=\s*"(.+)"', stripped)
            if name_match:
                current_name = name_match.group(1)
            elif ver_match:
                current_version = ver_match.group(1)
            elif stripped == "[[package]]" and current_name:
                if current_name and current_version:
                    self._dependencies.append(Dependency(
                        name=current_name,
                        version=current_version,
                        pinned=True,
                        source="Cargo.lock",
                    ))
                current_name = ""
                current_version = ""
        if current_name and current_version:
            self._dependencies.append(Dependency(
                name=current_name,
                version=current_version,
                pinned=True,
                source="Cargo.lock",
            ))

    def _parse_gemfile_lock(self, content: str) -> None:
        """Extract gems from Gemfile.lock."""
        in_specs = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "GEM" or stripped == "specs:":
                in_specs = True
                continue
            if in_specs and stripped and not stripped.startswith("("):
                match = re.match(r"^(\S+)\s+\(([^)]+)\)", stripped)
                if match:
                    self._dependencies.append(Dependency(
                        name=match.group(1),
                        version=match.group(2),
                        pinned=True,
                        source="Gemfile.lock",
                    ))
            elif in_specs and not stripped:
                in_specs = False

    # ------------------------------------------------------------------
    # 3. License Compliance
    # ------------------------------------------------------------------

    async def _check_license_compliance(self) -> None:
        """Detect licenses from dependency metadata and flag copyleft mixing."""
        cid = self.context.container_id
        if not cid or not self._dependencies:
            return

        # Try to extract license information from package.json files.
        for fpath, content in self._manifest_contents.items():
            if fpath.endswith("package.json"):
                try:
                    data = json.loads(content)
                    pkg_name = data.get("name", "")
                    license_val = data.get("license", "")
                    if pkg_name and license_val:
                        self._detected_licenses[pkg_name] = license_val
                except json.JSONDecodeError:
                    continue

        # Also try pip-licenses or similar inside the container.
        rc, stdout, _ = await self._exec_in_container(
            "sh", "-c",
            "pip list --format=json 2>/dev/null | head -200",
        )
        if rc == 0 and stdout.strip():
            try:
                pip_pkgs = json.loads(stdout)
                for pkg in pip_pkgs:
                    pkg_name = pkg.get("name", "")
                    # Try to get license from pip show.
                    rc2, show_out, _ = await self._exec_in_container(
                        "pip", "show", pkg_name,
                    )
                    if rc2 == 0:
                        for line in show_out.splitlines():
                            if line.startswith("License:"):
                                lic = line.split(":", 1)[1].strip()
                                if lic and lic != "UNKNOWN":
                                    self._detected_licenses[pkg_name] = lic
                                break
            except json.JSONDecodeError:
                pass

        if not self._detected_licenses:
            return

        copyleft_found: list[tuple[str, str]] = []
        permissive_found: list[tuple[str, str]] = []

        for pkg, lic in self._detected_licenses.items():
            lic_upper = lic.upper()
            if any(cl.upper() in lic_upper for cl in _COPYLEFT_LICENSES):
                copyleft_found.append((pkg, lic))
            elif any(pl.upper() in lic_upper for pl in _PERMISSIVE_LICENSES):
                permissive_found.append((pkg, lic))

        # Flag mixing of copyleft with permissive licenses.
        if copyleft_found and permissive_found:
            details = (
                "Copyleft:\n"
                + "\n".join(f"  {pkg}: {lic}" for pkg, lic in copyleft_found[:15])
                + "\nPermissive:\n"
                + "\n".join(f"  {pkg}: {lic}" for pkg, lic in permissive_found[:15])
            )
            self.add_finding(
                title=(
                    f"License compliance risk: copyleft/permissive mixing "
                    f"({len(copyleft_found)} copyleft packages)"
                ),
                description=(
                    f"Detected {len(copyleft_found)} package(s) under copyleft "
                    f"licenses (GPL/AGPL/LGPL) alongside {len(permissive_found)} "
                    "permissive-licensed packages. Combining copyleft-licensed "
                    "code with proprietary or permissively-licensed code may "
                    "impose unexpected distribution obligations."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="License mixing detected",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Review copyleft-licensed dependencies and ensure compliance "
                    "with their terms. Consider replacing GPL/AGPL packages with "
                    "permissively-licensed alternatives if the project is "
                    "proprietary. Consult legal counsel for complex licensing "
                    "scenarios."
                ),
                references=[
                    "https://www.gnu.org/licenses/gpl-faq.html",
                    "https://opensource.org/licenses",
                ],
                cvss_score=3.0,
                ai_risk_score=4.0,
            )
        elif copyleft_found:
            self.add_finding(
                title=f"Copyleft licenses detected ({len(copyleft_found)} packages)",
                description=(
                    f"Found {len(copyleft_found)} package(s) under copyleft "
                    "licenses. Ensure your usage complies with their terms."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Copyleft licenses found",
                        raw_data="\n".join(
                            f"  {pkg}: {lic}" for pkg, lic in copyleft_found[:20]
                        ),
                        location=f"container:{cid}",
                    )
                ],
            )

    # ------------------------------------------------------------------
    # 4. Dependency Tree Depth
    # ------------------------------------------------------------------

    async def _check_dependency_depth(self) -> None:
        """Analyse transitive dependency depth and flag deeply nested chains."""
        cid = self.context.container_id
        if not cid:
            return

        deep_chains: list[tuple[str, int, str]] = []  # (ecosystem, depth, snippet)

        # Check pip dependency tree via pipdeptree if available.
        rc, stdout, _ = await self._exec_in_container(
            "sh", "-c", "pipdeptree --json 2>/dev/null || pip show pip 2>/dev/null",
        )
        if rc == 0 and stdout.strip().startswith("["):
            try:
                tree = json.loads(stdout)
                for pkg in tree:
                    depth = self._measure_pip_depth(pkg, 0)
                    if depth > _MAX_DEPTH_THRESHOLD:
                        deep_chains.append((
                            "pip",
                            depth,
                            pkg.get("package", {}).get("key", "unknown"),
                        ))
            except json.JSONDecodeError:
                pass

        # Check npm dependency depth via package-lock.json.
        for fpath, content in self._manifest_contents.items():
            if fpath.endswith("package-lock.json"):
                try:
                    lock = json.loads(content)
                    packages = lock.get("packages", lock.get("dependencies", {}))
                    for path_key in packages:
                        depth = path_key.count("node_modules/")
                        if depth > _MAX_DEPTH_THRESHOLD:
                            pkg_name = path_key.rsplit("node_modules/", 1)[-1]
                            deep_chains.append(("npm", depth, pkg_name))
                except json.JSONDecodeError:
                    continue

        if deep_chains:
            details = "\n".join(
                f"  [{eco}] {name}: depth {depth}"
                for eco, depth, name in deep_chains[:20]
            )
            self.add_finding(
                title=(
                    f"Deeply nested dependency chains detected "
                    f"({len(deep_chains)} packages exceed depth {_MAX_DEPTH_THRESHOLD})"
                ),
                description=(
                    f"Found {len(deep_chains)} dependency chain(s) exceeding "
                    f"{_MAX_DEPTH_THRESHOLD} levels of transitive dependencies. "
                    "Deep dependency trees increase the supply chain attack "
                    "surface, make vulnerability remediation harder, and can "
                    "introduce unexpected transitive risks."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(deep_chains)} deeply nested chains",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Audit transitive dependencies and consider replacing "
                    "packages with deep dependency trees. Use tools like "
                    "pipdeptree or npm ls to visualise the dependency graph. "
                    "Prefer packages with fewer transitive dependencies."
                ),
                cvss_score=2.0,
                ai_risk_score=3.5,
            )

    @staticmethod
    def _measure_pip_depth(node: dict, current: int) -> int:
        """Recursively measure depth of a pipdeptree JSON node."""
        deps = node.get("dependencies", [])
        if not deps:
            return current
        return max(
            SBOMAgent._measure_pip_depth(child, current + 1)
            for child in deps
        )

    # ------------------------------------------------------------------
    # 5. Unpinned Version Detection
    # ------------------------------------------------------------------

    async def _check_unpinned_versions(self) -> None:
        """Scan parsed dependencies for unpinned or floating versions."""
        if not self._dependencies:
            return

        unpinned = [d for d in self._dependencies if not d.pinned]
        if not unpinned:
            return

        by_source: dict[str, list[Dependency]] = {}
        for dep in unpinned:
            by_source.setdefault(dep.source, []).append(dep)

        details_lines: list[str] = []
        for source, deps in by_source.items():
            pkg_names = ", ".join(d.name for d in deps[:10])
            suffix = f" (+{len(deps) - 10} more)" if len(deps) > 10 else ""
            details_lines.append(f"  {source}: {pkg_names}{suffix}")

        self.add_finding(
            title=f"Unpinned dependency versions ({len(unpinned)} packages)",
            description=(
                f"Found {len(unpinned)} dependency(ies) without pinned "
                f"versions across {len(by_source)} manifest file(s). "
                "Unpinned dependencies allow automatic installation of "
                "untested versions, enabling dependency confusion and "
                "supply chain injection attacks."
            ),
            severity=Severity.MEDIUM,
            owasp_llm=["LLM03"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MAP"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"{len(unpinned)} unpinned dependencies",
                    raw_data="\n".join(details_lines),
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Pin all dependencies to exact versions using == (pip), exact "
                "version strings (npm), or lock files. Use hash-checking mode "
                "where available (pip --require-hashes). Automate dependency "
                "updates with Dependabot, Renovate, or similar tools."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=5.5,
            ai_risk_score=6.0,
        )

    # ------------------------------------------------------------------
    # 6. Known CVE Cross-Reference
    # ------------------------------------------------------------------

    async def _check_known_cves(self) -> None:
        """Cross-reference dependencies against known CVEs using Trivy."""
        cid = self.context.container_id
        if not cid:
            return

        # Attempt to use Trivy for filesystem-level scanning.
        trivy_available = False
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            trivy_available = proc.returncode == 0
        except (FileNotFoundError, OSError):
            pass

        if trivy_available:
            await self._trivy_fs_scan(cid)
        else:
            await self._basic_cve_check()

    async def _trivy_fs_scan(self, cid: str) -> None:
        """Run ``trivy fs`` inside the container and parse results."""
        rc, stdout, stderr = await self._exec_in_container(
            "sh", "-c",
            "trivy fs --format json --severity CRITICAL,HIGH,MEDIUM / 2>/dev/null",
            timeout=120.0,
        )

        # Trivy may not be installed inside the container; try from the host
        # by copying the filesystem root.
        if rc != 0:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid,
                    "sh", "-c", "ls / >/dev/null 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()

                # Run trivy on the host, targeting the container filesystem.
                proc = await asyncio.create_subprocess_exec(
                    "trivy", "fs", "--format", "json",
                    "--severity", "CRITICAL,HIGH,MEDIUM",
                    "--timeout", "120s",
                    f"--input", f"/proc/1/root",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=180,
                )
                if proc.returncode == 0:
                    stdout = stdout_bytes.decode(errors="replace")
                    rc = 0
                else:
                    return
            except Exception:
                return

        if rc != 0:
            return

        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            logger.debug("Could not parse Trivy filesystem scan output")
            return

        results = report.get("Results", [])
        vulns_by_severity: dict[str, list[dict]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [],
        }

        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").upper()
                if sev in vulns_by_severity:
                    vulns_by_severity[sev].append({
                        "id": vuln.get("VulnerabilityID", ""),
                        "pkg": vuln.get("PkgName", ""),
                        "installed": vuln.get("InstalledVersion", ""),
                        "fixed": vuln.get("FixedVersion", ""),
                    })

        total_vulns = sum(len(v) for v in vulns_by_severity.values())
        if total_vulns == 0:
            return

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
        }

        for sev_label, vulns in vulns_by_severity.items():
            if not vulns:
                continue
            details = "\n".join(
                f"  {v['id']}: {v['pkg']}@{v['installed']} "
                f"(fix: {v['fixed'] or 'N/A'})"
                for v in vulns[:20]
            )
            self.add_finding(
                title=(
                    f"{sev_label.title()}-severity CVEs in container filesystem "
                    f"({len(vulns)} found)"
                ),
                description=(
                    f"Trivy filesystem scan found {len(vulns)} "
                    f"{sev_label.lower()}-severity vulnerability(ies) in "
                    f"installed packages within the container."
                ),
                severity=severity_map[sev_label],
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"{len(vulns)} {sev_label.lower()} CVEs",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Update affected packages to versions that address the "
                    "reported CVEs. Rebuild the container image after updates."
                ),
                cvss_score={"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0}[sev_label],
            )

    async def _basic_cve_check(self) -> None:
        """Perform rudimentary version-based risk flagging when Trivy is unavailable."""
        if not self._dependencies:
            return

        # Flag dependencies with no version at all as higher risk.
        no_version = [
            d for d in self._dependencies
            if not d.version or d.version in ("*", "latest", "")
        ]

        if no_version:
            self.add_finding(
                title=(
                    f"CVE scanner unavailable; {len(no_version)} unversioned "
                    f"dependencies detected"
                ),
                description=(
                    "Trivy is not available for CVE scanning. Additionally, "
                    f"{len(no_version)} dependencies have no version specified, "
                    "making it impossible to determine their vulnerability "
                    "status. Install Trivy for comprehensive vulnerability "
                    "analysis."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No CVE scanner; unversioned deps found",
                        raw_data="\n".join(
                            f"  {d.name} (source: {d.source})"
                            for d in no_version[:20]
                        ),
                    )
                ],
                remediation=(
                    "Install Trivy for filesystem-level CVE scanning: "
                    "https://aquasecurity.github.io/trivy/. Pin all "
                    "dependency versions to enable accurate vulnerability "
                    "tracking."
                ),
            )

    # ------------------------------------------------------------------
    # 7. SBOM Generation (CycloneDX)
    # ------------------------------------------------------------------

    async def _generate_sbom(self) -> None:
        """Generate a minimal CycloneDX JSON SBOM and store it in context metadata."""
        if not self._dependencies:
            logger.debug("No dependencies found; skipping SBOM generation")
            return

        components: list[dict[str, Any]] = []
        seen: set[str] = set()

        for dep in self._dependencies:
            key = f"{dep.source}:{dep.name}:{dep.version}"
            if key in seen:
                continue
            seen.add(key)

            purl = self._build_purl(dep)
            component: dict[str, Any] = {
                "type": "library",
                "name": dep.name,
                "version": dep.version or "unspecified",
            }
            if purl:
                component["purl"] = purl

            # Attach license if known.
            lic = self._detected_licenses.get(dep.name)
            if lic:
                component["licenses"] = [{"license": {"id": lic}}]

            components.append(component)

        sbom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "AiSec",
                        "name": "sbom-agent",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.context.target_name or self.context.target_image or "unknown",
                },
            },
            "components": components,
        }

        # Store in scan context metadata for downstream consumers.
        self.context.metadata["generated_sbom"] = sbom
        self.context.metadata["generated_sbom_json"] = json.dumps(
            sbom, indent=2, default=str,
        )

        self.add_finding(
            title=f"CycloneDX SBOM generated ({len(components)} components)",
            description=(
                f"Generated a CycloneDX 1.5 SBOM containing "
                f"{len(components)} unique component(s) from discovered "
                "dependency manifests. The SBOM is stored in scan metadata "
                "for export and compliance reporting."
            ),
            severity=Severity.INFO,
            owasp_llm=["LLM03"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["MAP"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"CycloneDX SBOM with {len(components)} components",
                    raw_data=json.dumps(sbom, indent=2, default=str)[:2000],
                    location="scan_metadata:generated_sbom",
                )
            ],
        )

    @staticmethod
    def _build_purl(dep: Dependency) -> str:
        """Build a Package URL (purl) for a dependency."""
        source_to_type = {
            "requirements.txt": "pypi",
            "requirements-dev.txt": "pypi",
            "Pipfile.lock": "pypi",
            "poetry.lock": "pypi",
            "package.json": "npm",
            "package-lock.json": "npm",
            "go.sum": "golang",
            "go.mod": "golang",
            "Cargo.lock": "cargo",
            "Cargo.toml": "cargo",
            "Gemfile.lock": "gem",
            "Gemfile": "gem",
        }
        pkg_type = source_to_type.get(dep.source, "generic")
        version = dep.version or "unspecified"
        name = dep.name.replace("/", "%2F") if pkg_type != "golang" else dep.name
        return f"pkg:{pkg_type}/{name}@{version}"
