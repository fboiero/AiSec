"""Static code analysis agent using Semgrep, Bandit, and built-in patterns."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Built-in dangerous code patterns (fallback when external tools unavailable)
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "eval/exec with dynamic input",
        re.compile(
            r"(?:eval|exec)\s*\(\s*(?![\"\'])"
            r"(?:.*(?:input|request|response|result|output|data|user|prompt|query|message|llm|completion))",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Dynamic eval/exec can execute arbitrary code from untrusted input.",
        "Replace eval/exec with safe alternatives. Use ast.literal_eval() for data "
        "parsing. Never evaluate LLM outputs directly.",
    ),
    (
        "subprocess with shell=True",
        re.compile(
            r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
            re.DOTALL,
        ),
        Severity.HIGH,
        "subprocess with shell=True enables shell injection attacks.",
        "Use subprocess with shell=False and pass arguments as a list.",
    ),
    (
        "pickle.load from untrusted source",
        re.compile(
            r"pickle\.(?:load|loads)\s*\(",
        ),
        Severity.HIGH,
        "Pickle deserialization can execute arbitrary code. Model files using pickle "
        "format are a known attack vector for supply chain attacks.",
        "Use safetensors or other safe serialization formats for model files. "
        "Never unpickle data from untrusted sources.",
    ),
    (
        "os.system with f-string or format",
        re.compile(
            r"os\.system\s*\(\s*(?:f[\"']|[\"'].*\.format)",
        ),
        Severity.CRITICAL,
        "os.system with string interpolation enables command injection.",
        "Use subprocess with shell=False and argument lists instead of os.system.",
    ),
    (
        "yaml.load without SafeLoader",
        re.compile(
            r"yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:Safe|CSafe)Loader)",
        ),
        Severity.MEDIUM,
        "yaml.load without SafeLoader can execute arbitrary Python code.",
        "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader).",
    ),
    (
        "Hardcoded API key pattern",
        re.compile(
            r"(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)"
            r"\s*[=:]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Hardcoded API key or secret detected in source code.",
        "Use environment variables or a secrets manager for API keys. "
        "Never commit credentials to source code.",
    ),
    (
        "torch.load without weights_only",
        re.compile(
            r"torch\.load\s*\([^)]*\)(?!.*weights_only\s*=\s*True)",
        ),
        Severity.HIGH,
        "torch.load uses pickle internally and can execute arbitrary code.",
        "Use torch.load(path, weights_only=True) or switch to safetensors format.",
    ),
    (
        "Prompt template with f-string injection",
        re.compile(
            r"(?:system[_\s]*(?:prompt|message|instruction)|role.*system)"
            r".*f[\"'].*\{.*\}",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.MEDIUM,
        "System prompt built with f-string may allow prompt injection through "
        "interpolated variables.",
        "Use parameterized prompt templates instead of f-strings for system prompts. "
        "Validate and sanitize all interpolated values.",
    ),
]

# File extensions to scan
SOURCE_EXTENSIONS = {"*.py", "*.js", "*.ts", "*.go", "*.yaml", "*.yml", "*.json"}

# Path to bundled AI security rules
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class StaticAnalysisAgent(BaseAgent):
    """Static code security analysis using Semgrep, Bandit, and built-in patterns."""

    name: ClassVar[str] = "static_analysis"
    description: ClassVar[str] = (
        "Performs static code analysis using Semgrep (with AI-specific rules), "
        "Bandit (Python security linting), and built-in pattern matching for "
        "dangerous code constructs."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM05", "LLM06", "ASI01", "ASI02", "ASI05"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run static analysis checks."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files found for static analysis",
                description=(
                    "No source code files were found in the container image. "
                    "Static analysis could not be performed."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
                remediation="Ensure source code is included in the image for analysis.",
            )
            return

        semgrep_ran = await self._run_semgrep(source_files)
        bandit_ran = await self._run_bandit(source_files)

        # Always run built-in patterns as a complement
        await self._run_builtin_patterns(source_files)

        if not semgrep_ran and not bandit_ran:
            self.add_finding(
                title="External static analysis tools unavailable",
                description=(
                    "Neither Semgrep nor Bandit are installed. Only built-in "
                    "pattern matching was used. Install semgrep and/or bandit "
                    "for deeper static analysis coverage."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
                remediation="pip install semgrep bandit",
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect source file paths from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        extensions = " -o ".join(f"-name '{ext}'" for ext in SOURCE_EXTENSIONS)
        cmd = (
            f"find /app /src /opt -maxdepth 6 -type f "
            f"\\( {extensions} \\) -size -1M 2>/dev/null | head -200"
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

    async def _run_semgrep(self, source_files: list[str]) -> bool:
        """Run Semgrep with auto config and AI-specific rules."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False
        except (FileNotFoundError, OSError):
            return False

        # Determine source directory from collected files
        source_dirs = {str(Path(f).parent) for f in source_files[:10]}
        target_dir = min(source_dirs, key=len) if source_dirs else "/app"

        # Build semgrep command
        cmd = ["semgrep", "scan", "--config", "auto", "--json", target_dir]

        # Add custom AI rules if available
        ai_rules = _RULES_DIR / "ai_security.yaml"
        if ai_rules.exists():
            cmd = [
                "semgrep", "scan",
                "--config", "auto",
                "--config", str(ai_rules),
                "--json", target_dir,
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode(errors="replace")

            if not output.strip():
                return True

            data = json.loads(output)
            results = data.get("results", [])

            for result in results:
                severity_map = {
                    "ERROR": Severity.HIGH,
                    "WARNING": Severity.MEDIUM,
                    "INFO": Severity.LOW,
                }
                sev = severity_map.get(
                    result.get("extra", {}).get("severity", "WARNING"),
                    Severity.MEDIUM,
                )
                check_id = result.get("check_id", "unknown")
                message = result.get("extra", {}).get("message", "")
                path = result.get("path", "")
                line = result.get("start", {}).get("line", 0)
                snippet = result.get("extra", {}).get("lines", "")

                self.add_finding(
                    title=f"Semgrep: {check_id}",
                    description=message or f"Semgrep rule {check_id} matched.",
                    severity=sev,
                    owasp_llm=["LLM05", "LLM06"],
                    owasp_agentic=["ASI05"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"Semgrep match at {path}:{line}",
                            raw_data=snippet[:500],
                            location=path,
                        )
                    ],
                    remediation=result.get("extra", {}).get("fix", "Review and fix the flagged code."),
                )

            return True
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("Semgrep execution failed: %s", exc)
            return True  # Tool was available even if parsing failed

    async def _run_bandit(self, source_files: list[str]) -> bool:
        """Run Bandit on Python source files."""
        py_files = [f for f in source_files if f.endswith(".py")]
        if not py_files:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False
        except (FileNotFoundError, OSError):
            return False

        # Find the common Python source directory
        py_dirs = {str(Path(f).parent) for f in py_files[:10]}
        target_dir = min(py_dirs, key=len) if py_dirs else "/app"

        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "-r", target_dir, "-f", "json", "-ll",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors="replace")

            if not output.strip():
                return True

            data = json.loads(output)
            results = data.get("results", [])

            severity_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }

            for result in results:
                sev = severity_map.get(result.get("issue_severity", "MEDIUM"), Severity.MEDIUM)
                confidence = result.get("issue_confidence", "MEDIUM")
                test_id = result.get("test_id", "")
                issue_text = result.get("issue_text", "")
                filename = result.get("filename", "")
                line_number = result.get("line_number", 0)
                code = result.get("code", "")

                # Skip low-confidence findings
                if confidence == "LOW":
                    continue

                self.add_finding(
                    title=f"Bandit {test_id}: {issue_text}",
                    description=(
                        f"Bandit security issue ({confidence} confidence): {issue_text}"
                    ),
                    severity=sev,
                    owasp_llm=["LLM05", "LLM06"],
                    owasp_agentic=["ASI05"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"Bandit {test_id} at {filename}:{line_number}",
                            raw_data=code[:500],
                            location=f"{filename}:{line_number}",
                        )
                    ],
                    remediation=result.get("more_info", "Review the Bandit documentation for this issue."),
                    references=[result["more_info"]] if result.get("more_info") else [],
                    cvss_score=7.0 if sev == Severity.HIGH else 5.0,
                )

            return True
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("Bandit execution failed: %s", exc)
            return True

    async def _run_builtin_patterns(self, source_files: list[str]) -> None:
        """Run built-in pattern matching on source files in the container."""
        cid = self.context.container_id
        if not cid:
            return

        all_hits: list[tuple[str, str, str, Severity, str]] = []

        for fpath in source_files[:100]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "65536", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    continue
                content = stdout.decode(errors="replace")
            except Exception:
                continue

            for pattern_name, regex, severity, desc, remediation in DANGEROUS_PATTERNS:
                matches = list(regex.finditer(content))
                for m in matches[:3]:
                    start = max(0, m.start() - 40)
                    end = min(len(content), m.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    all_hits.append((pattern_name, fpath, snippet, severity, remediation))

        if not all_hits:
            return

        # Group by pattern name
        by_pattern: dict[str, list[tuple[str, str, Severity, str]]] = {}
        for name, fpath, snippet, sev, rem in all_hits:
            by_pattern.setdefault(name, []).append((fpath, snippet, sev, rem))

        for pattern_name, hits in by_pattern.items():
            worst_sev = min(
                (sev for _, _, sev, _ in hits),
                key=lambda s: list(Severity).index(s),
            )
            details = "\n".join(
                f"  {fpath}: {snippet[:120]}"
                for fpath, snippet, _, _ in hits[:10]
            )

            self.add_finding(
                title=f"Static pattern: {pattern_name} ({len(hits)} instances)",
                description=(
                    f"Built-in static analysis detected {len(hits)} instance(s) of "
                    f"'{pattern_name}' pattern in source code. "
                    + DANGEROUS_PATTERNS[
                        next(
                            i for i, (n, *_) in enumerate(DANGEROUS_PATTERNS)
                            if n == pattern_name
                        )
                    ][3]
                ),
                severity=worst_sev,
                owasp_llm=["LLM01", "LLM05", "LLM06"],
                owasp_agentic=["ASI01", "ASI05"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(hits)} matches for '{pattern_name}'",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=hits[0][3],
                cvss_score=9.0 if worst_sev == Severity.CRITICAL else 7.0,
                ai_risk_score=8.0,
            )
