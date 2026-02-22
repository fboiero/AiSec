"""Resource exhaustion and DoS vector detection agent."""

from __future__ import annotations

import ast
import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ReDoS patterns: regex with catastrophic backtracking
REDOS_INDICATORS = [
    re.compile(r"\([^)]*[+*]\)[+*]"),           # (a+)+, (a*)*
    re.compile(r"\([^)]*\|[^)]*\)[+*]"),         # (a|a)*
    re.compile(r"\([^)]*[+*][^)]*[+*][^)]*\)"),  # nested quantifiers
    re.compile(r"\\[dDwWsS][+*].*\\[dDwWsS][+*].*[+*]"),  # \d+.*\d+.*+
]

# Patterns for missing timeouts in HTTP clients
HTTP_NO_TIMEOUT: list[tuple[str, re.Pattern[str], str]] = [
    (
        "requests without timeout",
        re.compile(r"requests\.(?:get|post|put|delete|patch|head|options)\s*\([^)]*\)(?!.*timeout)"),
        "Add timeout parameter: requests.get(url, timeout=30)",
    ),
    (
        "httpx without timeout",
        re.compile(r"httpx\.(?:get|post|put|delete|patch|head|options|Client|AsyncClient)\s*\([^)]*\)(?!.*timeout)"),
        "Add timeout parameter: httpx.get(url, timeout=30)",
    ),
    (
        "urllib without timeout",
        re.compile(r"urllib\.request\.urlopen\s*\([^)]*\)(?!.*timeout)"),
        "Add timeout parameter: urlopen(url, timeout=30)",
    ),
    (
        "aiohttp without timeout",
        re.compile(r"aiohttp\.ClientSession\s*\([^)]*\)(?!.*timeout)"),
        "Pass aiohttp.ClientTimeout to session: ClientSession(timeout=ClientTimeout(total=30))",
    ),
]

# Zip bomb patterns
ZIP_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "zipfile.extractall without size check",
        re.compile(r"\.extractall\s*\("),
        "Check individual file sizes before extraction. Set a maximum total size.",
    ),
    (
        "tarfile.extractall without filter",
        re.compile(r"tarfile\.open.*\.extractall\s*\([^)]*\)(?!.*filter)"),
        "Use tarfile.extractall(filter='data') to prevent path traversal and symlink attacks.",
    ),
]

# Unbounded read patterns
UNBOUNDED_READ_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "Unbounded file read",
        re.compile(r"open\s*\([^)]*\)\.read\s*\(\s*\)"),
        "Use read(max_size) with a size limit instead of unbounded read().",
    ),
    (
        "Unbounded response read",
        re.compile(r"\.content(?!\s*\[)|\.text(?!\s*\[)"),
        "Stream large responses with iter_content() or iter_lines().",
    ),
]

# Memory allocation patterns
MEMORY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "String/bytes multiplication with variable",
        re.compile(r'(?:b?["\'][^"\']*["\']|b"[^"]*")\s*\*\s*(?![0-9])'),
        "Validate the multiplier to prevent memory exhaustion.",
    ),
    (
        "list() on unbounded iterator",
        re.compile(r"list\s*\(\s*(?:map|filter|range|itertools)"),
        "Use itertools.islice() or set a maximum size before converting to list.",
    ),
]


class ResourceExhaustionAgent(BaseAgent):
    """Detects resource exhaustion and denial-of-service vectors."""

    name: ClassVar[str] = "resource_exhaustion"
    description: ClassVar[str] = (
        "Detects ReDoS patterns, zip bombs, unbounded loops, missing timeouts, "
        "memory allocation bombs, and other resource exhaustion vectors."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM04", "ASI02", "ASI10"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Scan for resource exhaustion vectors."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for resource exhaustion analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM04"],
            )
            return

        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if not content:
                continue

            self._check_redos(content, fpath)
            self._check_missing_timeouts(content, fpath)
            self._check_zip_bombs(content, fpath)
            self._check_unbounded_reads(content, fpath)
            self._check_memory_patterns(content, fpath)
            self._check_unbounded_loops(content, fpath)
            self._check_missing_recursion_limit(content, fpath)

    def _check_redos(self, content: str, fpath: str) -> None:
        """Check for ReDoS-vulnerable regex patterns."""
        # Find all regex compile/search/match calls
        regex_pattern = re.compile(
            r're\.(?:compile|search|match|findall|finditer|sub|split)'
            r'\s*\(\s*(?:r)?["\']([^"\']+)["\']',
        )

        for m in regex_pattern.finditer(content):
            regex_str = m.group(1)
            for indicator in REDOS_INDICATORS:
                if indicator.search(regex_str):
                    line_num = content[:m.start()].count("\n") + 1
                    self.add_finding(
                        title=f"ReDoS: catastrophic backtracking in regex",
                        description=(
                            f"Regex pattern '{regex_str[:60]}' at {fpath}:{line_num} "
                            "contains nested quantifiers that can cause catastrophic "
                            "backtracking, leading to denial of service."
                        ),
                        severity=Severity.HIGH,
                        owasp_llm=["LLM04"],
                        owasp_agentic=["ASI10"],
                        nist_ai_rmf=["MEASURE"],
                        evidence=[
                            Evidence(
                                type="file_content",
                                summary=f"ReDoS pattern at {fpath}:{line_num}",
                                raw_data=f"Pattern: {regex_str[:200]}",
                                location=f"{fpath}:{line_num}",
                            )
                        ],
                        remediation=(
                            "Simplify the regex to avoid nested quantifiers. Use "
                            "re2 or regex module with timeout. Consider using "
                            "non-backtracking patterns."
                        ),
                        cvss_score=7.5,
                    )
                    break

    def _check_missing_timeouts(self, content: str, fpath: str) -> None:
        """Check for HTTP calls missing timeout parameters."""
        for name, pattern, remediation in HTTP_NO_TIMEOUT:
            matches = list(pattern.finditer(content))
            if matches:
                lines = [str(content[:m.start()].count("\n") + 1) for m in matches[:5]]
                self.add_finding(
                    title=f"Missing timeout: {name} ({len(matches)} calls)",
                    description=(
                        f"Found {len(matches)} HTTP call(s) without timeout parameter "
                        f"at {fpath} (lines: {', '.join(lines)}). Without timeouts, "
                        "connections can hang indefinitely, exhausting resources."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM04"],
                    owasp_agentic=["ASI10"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"{name} at {fpath}",
                            raw_data=f"Lines: {', '.join(lines)}",
                            location=fpath,
                        )
                    ],
                    remediation=remediation,
                    cvss_score=5.0,
                )

    def _check_zip_bombs(self, content: str, fpath: str) -> None:
        """Check for zip/tar extraction without size validation."""
        for name, pattern, remediation in ZIP_PATTERNS:
            matches = list(pattern.finditer(content))
            for m in matches[:3]:
                line_num = content[:m.start()].count("\n") + 1
                self.add_finding(
                    title=f"Zip bomb risk: {name}",
                    description=(
                        f"Archive extraction at {fpath}:{line_num} without size "
                        "validation. This can be exploited with zip bombs or tar "
                        "bombs to exhaust disk space and memory."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM04"],
                    owasp_agentic=["ASI02"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"{name} at {fpath}:{line_num}",
                            raw_data=content[max(0, m.start() - 30):m.end() + 60][:200],
                            location=f"{fpath}:{line_num}",
                        )
                    ],
                    remediation=remediation,
                    cvss_score=7.0,
                )

    def _check_unbounded_reads(self, content: str, fpath: str) -> None:
        """Check for unbounded file/response reads."""
        for name, pattern, remediation in UNBOUNDED_READ_PATTERNS:
            matches = list(pattern.finditer(content))
            if len(matches) > 2:
                self.add_finding(
                    title=f"Unbounded read: {name} ({len(matches)} instances)",
                    description=(
                        f"Found {len(matches)} instance(s) of unbounded read "
                        f"at {fpath}. Reading entire files or responses without "
                        "size limits can lead to memory exhaustion."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM04"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"{name} at {fpath}",
                            raw_data=f"Instances: {len(matches)}",
                            location=fpath,
                        )
                    ],
                    remediation=remediation,
                    cvss_score=4.0,
                )

    def _check_memory_patterns(self, content: str, fpath: str) -> None:
        """Check for memory allocation amplification."""
        for name, pattern, remediation in MEMORY_PATTERNS:
            matches = list(pattern.finditer(content))
            for m in matches[:3]:
                line_num = content[:m.start()].count("\n") + 1
                snippet = content[max(0, m.start() - 20):m.end() + 40][:120].strip()
                self.add_finding(
                    title=f"Memory exhaustion risk: {name}",
                    description=(
                        f"Potential memory allocation amplification at {fpath}:{line_num}: "
                        f"'{snippet}'. If the multiplier is user-controlled, this can "
                        "exhaust available memory."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM04"],
                    owasp_agentic=["ASI02"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"{name} at {fpath}:{line_num}",
                            raw_data=snippet,
                            location=f"{fpath}:{line_num}",
                        )
                    ],
                    remediation=remediation,
                    cvss_score=5.0,
                )

    def _check_unbounded_loops(self, content: str, fpath: str) -> None:
        """Check for while True loops without break/timeout using AST."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                # Check for while True
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    has_break = any(
                        isinstance(n, ast.Break) for n in ast.walk(node)
                    )
                    has_return = any(
                        isinstance(n, ast.Return) for n in ast.walk(node)
                    )
                    if not has_break and not has_return:
                        self.add_finding(
                            title="Unbounded loop: while True without break",
                            description=(
                                f"Infinite loop at {fpath}:{node.lineno} without "
                                "break or return statement. This will hang the process."
                            ),
                            severity=Severity.HIGH,
                            owasp_llm=["LLM04"],
                            owasp_agentic=["ASI10"],
                            evidence=[
                                Evidence(
                                    type="file_content",
                                    summary=f"while True at {fpath}:{node.lineno}",
                                    raw_data=f"Line {node.lineno}: while True without break",
                                    location=f"{fpath}:{node.lineno}",
                                )
                            ],
                            remediation="Add a break condition, timeout, or maximum iteration count.",
                            cvss_score=6.0,
                        )

    def _check_missing_recursion_limit(self, content: str, fpath: str) -> None:
        """Check for recursive functions without depth limits."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if function calls itself
                func_name = node.name
                calls_self = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name) and child.func.id == func_name:
                            calls_self = True
                            break

                if calls_self:
                    # Check if there's a depth/limit parameter
                    has_depth_param = any(
                        arg.arg in ("depth", "max_depth", "level", "limit", "max_level", "remaining")
                        for arg in node.args.args
                    )
                    if not has_depth_param:
                        self.add_finding(
                            title=f"Recursive function without depth limit: {func_name}",
                            description=(
                                f"Recursive function '{func_name}' at {fpath}:{node.lineno} "
                                "has no depth/limit parameter. This could lead to stack "
                                "overflow with deep or circular input."
                            ),
                            severity=Severity.MEDIUM,
                            owasp_llm=["LLM04"],
                            evidence=[
                                Evidence(
                                    type="file_content",
                                    summary=f"Recursive {func_name} at {fpath}:{node.lineno}",
                                    raw_data=f"def {func_name}(...) calls itself without depth limit",
                                    location=f"{fpath}:{node.lineno}",
                                )
                            ],
                            remediation="Add a max_depth parameter and check it at the start of the function.",
                            cvss_score=4.0,
                        )

    async def _collect_source_files(self) -> list[str]:
        """Collect Python source files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f -name '*.py' "
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
