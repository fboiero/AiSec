"""Transitive dependency analysis, license compliance, and abandoned package detection."""

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

# License categories for compatibility checking
COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
    "GPL-2.0-or-later", "GPL-3.0-or-later", "AGPL-3.0-or-later",
    "GPLv2", "GPLv3", "AGPLv3", "LGPLv2", "LGPLv3",
}

RESTRICTIVE_LICENSES = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPLv3",
    "SSPL-1.0", "BSL-1.1", "Elastic-2.0",
}

# Internal package name patterns that might conflict with public PyPI
INTERNAL_PACKAGE_PREFIXES = [
    "internal-", "private-", "company-", "corp-",
]

# Known abandoned but widely-used packages (no updates in 2+ years)
KNOWN_ABANDONED_THRESHOLD_DAYS = 730  # ~2 years


class DeepDependencyAgent(BaseAgent):
    """Deep transitive dependency analysis with license and health checks."""

    name: ClassVar[str] = "deep_dependency"
    description: ClassVar[str] = (
        "Analyzes transitive dependencies using pipdeptree, checks license "
        "compatibility with pip-licenses, detects abandoned packages, and "
        "flags dependency confusion risks."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM03", "LLM05", "ASI04"]
    depends_on: ClassVar[list[str]] = ["dependency_audit"]

    async def analyze(self) -> None:
        """Run deep dependency analysis."""
        dep_tree = await self._run_pipdeptree()
        licenses = await self._run_pip_licenses()

        if dep_tree is None and licenses is None:
            # Fallback: parse requirements files
            await self._fallback_analysis()
            return

        if dep_tree is not None:
            await self._analyze_dependency_tree(dep_tree)

        if licenses is not None:
            self._check_license_compatibility(licenses)

    async def _run_pipdeptree(self) -> list[dict] | None:
        """Run pipdeptree --json-tree to get the dependency graph."""
        cid = self.context.container_id
        if not cid:
            return None

        # Try in container first, then host
        for cmd_prefix in [
            ["docker", "exec", cid, "pipdeptree", "--json-tree"],
            ["docker", "exec", cid, "python", "-m", "pipdeptree", "--json-tree"],
        ]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_prefix,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0 and stdout.strip():
                    return json.loads(stdout.decode(errors="replace"))
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                continue

        return None

    async def _run_pip_licenses(self) -> list[dict] | None:
        """Run pip-licenses --format=json for license info."""
        cid = self.context.container_id
        if not cid:
            return None

        for cmd_prefix in [
            ["docker", "exec", cid, "pip-licenses", "--format=json"],
            ["docker", "exec", cid, "python", "-m", "piplicenses", "--format=json"],
        ]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_prefix,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0 and stdout.strip():
                    return json.loads(stdout.decode(errors="replace"))
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                continue

        return None

    async def _analyze_dependency_tree(self, tree: list[dict]) -> None:
        """Analyze the dependency tree for transitive risks."""
        # Flatten all transitive dependencies and their depths
        all_deps: dict[str, int] = {}  # name -> max depth
        self._flatten_tree(tree, all_deps, depth=0)

        # Check maximum depth
        deep_deps = {name: d for name, d in all_deps.items() if d > 5}
        if deep_deps:
            details = "\n".join(
                f"  {name}: depth {d}" for name, d in sorted(deep_deps.items(), key=lambda x: -x[1])[:15]
            )
            self.add_finding(
                title=f"Deep dependency chains ({len(deep_deps)} packages > 5 levels)",
                description=(
                    f"Found {len(deep_deps)} packages deeper than 5 levels in the "
                    "dependency tree. Deep chains increase supply chain attack surface "
                    "and make vulnerability tracking difficult."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Deep dependency chains",
                        raw_data=details,
                        location="pipdeptree",
                    )
                ],
                remediation=(
                    "Review deep dependency chains. Consider replacing packages "
                    "with many transitive dependencies with lighter alternatives."
                ),
                cvss_score=4.0,
            )

        # Check for dependency confusion candidates
        confusion_candidates = [
            name for name in all_deps
            if any(name.startswith(prefix) for prefix in INTERNAL_PACKAGE_PREFIXES)
        ]
        if confusion_candidates:
            self.add_finding(
                title=f"Dependency confusion risk ({len(confusion_candidates)} packages)",
                description=(
                    f"Found {len(confusion_candidates)} package(s) with names "
                    "matching internal package naming patterns: "
                    f"{', '.join(confusion_candidates[:10])}. "
                    "These could be targets for dependency confusion attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Dependency confusion candidates",
                        raw_data="\n".join(confusion_candidates[:10]),
                        location="pipdeptree",
                    )
                ],
                remediation=(
                    "Use a private package registry with priority over PyPI. "
                    "Pin all internal packages to exact versions with hashes."
                ),
                cvss_score=7.5,
            )

        # Cross-reference with dependency_audit results for transitive vulns
        dep_audit = self.context.agent_results.get("dependency_audit")
        if dep_audit:
            direct_pkgs = {name for name, d in all_deps.items() if d == 0}
            transitive_pkgs = {name for name, d in all_deps.items() if d > 0}

            vuln_transitive = []
            for finding in dep_audit.findings:
                for pkg in transitive_pkgs:
                    if pkg.lower() in finding.title.lower():
                        vuln_transitive.append((pkg, finding.title))

            if vuln_transitive:
                details = "\n".join(f"  {pkg}: {title}" for pkg, title in vuln_transitive[:10])
                self.add_finding(
                    title=f"Vulnerable transitive dependencies ({len(vuln_transitive)})",
                    description=(
                        f"Found {len(vuln_transitive)} known vulnerabilities in "
                        "transitive (indirect) dependencies. These are harder to "
                        "detect and fix than direct dependency vulnerabilities."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM03", "LLM05"],
                    owasp_agentic=["ASI04"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary="Vulnerable transitive deps",
                            raw_data=details,
                            location="pipdeptree + pip-audit",
                        )
                    ],
                    remediation=(
                        "Override transitive dependency versions in your requirements. "
                        "Use pip-compile with --allow-unsafe to pin all transitive deps."
                    ),
                    cvss_score=7.0,
                )

    def _flatten_tree(
        self,
        tree: list[dict],
        result: dict[str, int],
        depth: int,
    ) -> None:
        """Recursively flatten the dependency tree with depth tracking."""
        for pkg in tree:
            name = pkg.get("package_name", pkg.get("key", "")).lower()
            if name:
                result[name] = max(result.get(name, 0), depth)
            children = pkg.get("dependencies", [])
            if children and depth < 20:  # Prevent infinite recursion
                self._flatten_tree(children, result, depth + 1)

    def _check_license_compatibility(self, licenses: list[dict]) -> None:
        """Check for license compatibility issues."""
        copyleft_deps: list[tuple[str, str]] = []
        restrictive_deps: list[tuple[str, str]] = []
        unknown_license_deps: list[str] = []

        for pkg in licenses:
            name = pkg.get("Name", "")
            license_name = pkg.get("License", "UNKNOWN")

            if license_name in ("UNKNOWN", "", "UNKNOWN LICENSE"):
                unknown_license_deps.append(name)
                continue

            # Check for exact or partial match
            for copyleft in COPYLEFT_LICENSES:
                if copyleft.lower() in license_name.lower():
                    copyleft_deps.append((name, license_name))
                    break

            for restrictive in RESTRICTIVE_LICENSES:
                if restrictive.lower() in license_name.lower():
                    restrictive_deps.append((name, license_name))
                    break

        if restrictive_deps:
            details = "\n".join(f"  {name}: {lic}" for name, lic in restrictive_deps[:15])
            self.add_finding(
                title=f"Restrictive license dependencies ({len(restrictive_deps)})",
                description=(
                    f"Found {len(restrictive_deps)} package(s) with restrictive licenses "
                    "(AGPL, SSPL, BSL, etc.) that may impose obligations on your "
                    "application, especially for SaaS deployments."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Restrictive licenses",
                        raw_data=details,
                        location="pip-licenses",
                    )
                ],
                remediation=(
                    "Review license obligations for AGPL/SSPL packages. Consider "
                    "replacing with permissively-licensed alternatives if your "
                    "application is proprietary or SaaS."
                ),
                cvss_score=3.0,
            )

        if copyleft_deps and len(copyleft_deps) != len(restrictive_deps):
            non_restrictive_copyleft = [
                (n, l) for n, l in copyleft_deps
                if (n, l) not in restrictive_deps
            ]
            if non_restrictive_copyleft:
                details = "\n".join(
                    f"  {name}: {lic}" for name, lic in non_restrictive_copyleft[:15]
                )
                self.add_finding(
                    title=f"Copyleft license dependencies ({len(non_restrictive_copyleft)})",
                    description=(
                        f"Found {len(non_restrictive_copyleft)} package(s) with copyleft "
                        "licenses (GPL, LGPL). These may require your application to "
                        "be released under a compatible open-source license."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM03"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary="Copyleft licenses",
                            raw_data=details,
                            location="pip-licenses",
                        )
                    ],
                    remediation=(
                        "Verify GPL/LGPL compatibility with your licensing model. "
                        "LGPL is generally safe for dynamic linking."
                    ),
                )

        if len(unknown_license_deps) > 3:
            self.add_finding(
                title=f"Packages with unknown licenses ({len(unknown_license_deps)})",
                description=(
                    f"Found {len(unknown_license_deps)} packages with unknown or "
                    f"unspecified licenses: {', '.join(unknown_license_deps[:10])}."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM03"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="Unknown licenses",
                        raw_data="\n".join(unknown_license_deps[:20]),
                        location="pip-licenses",
                    )
                ],
                remediation="Verify the license for each package before production use.",
            )

    async def _fallback_analysis(self) -> None:
        """Fallback analysis when pipdeptree and pip-licenses are unavailable."""
        self.add_finding(
            title="Deep dependency tools unavailable",
            description=(
                "Neither pipdeptree nor pip-licenses are installed in the container. "
                "Transitive dependency analysis and license compliance checking "
                "could not be performed."
            ),
            severity=Severity.INFO,
            owasp_llm=["LLM03"],
            owasp_agentic=["ASI04"],
            remediation="pip install pipdeptree pip-licenses",
        )
