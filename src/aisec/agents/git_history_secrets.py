"""Git commit history secret scanning agent."""

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

# Secret patterns for fallback scanning (when gitleaks unavailable)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{32,}"), Severity.CRITICAL),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{32,}"), Severity.CRITICAL),
    ("HuggingFace token", re.compile(r"hf_[A-Za-z0-9]{20,}"), Severity.HIGH),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("GCP API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), Severity.HIGH),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Connection string", re.compile(r"(?:postgresql|mongodb|redis|mysql)://[^\s'\"]{10,}"), Severity.HIGH),
    ("JWT token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"), Severity.HIGH),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), Severity.HIGH),
    ("Stripe key", re.compile(r"(?:sk|pk)_live_[0-9a-zA-Z]{24,}"), Severity.CRITICAL),
    ("Generic secret assignment", re.compile(r'(?:secret|password|passwd|api_key|token)\s*[=:]\s*["\'][^\s"\']{8,}["\']', re.IGNORECASE), Severity.MEDIUM),
    ("GitHub token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"), Severity.HIGH),
    ("SendGrid key", re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}"), Severity.HIGH),
]


class GitHistorySecretsAgent(BaseAgent):
    """Scans git commit history for leaked secrets."""

    name: ClassVar[str] = "git_history_secrets"
    description: ClassVar[str] = (
        "Scans git commit history for leaked secrets (API keys, private keys, "
        "connection strings, tokens) using gitleaks with fallback to built-in "
        "regex patterns. Differentiates current HEAD secrets from historical ones."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM01", "ASI04"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Scan git history for secrets."""
        has_git = await self._check_git_directory()
        if not has_git:
            self.add_finding(
                title="No git repository found",
                description=(
                    "No .git directory found in the container. "
                    "Git history secret scanning could not be performed."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM01"],
            )
            return

        # Try gitleaks first, fallback to built-in
        gitleaks_ran = await self._run_gitleaks()
        if not gitleaks_ran:
            await self._run_builtin_scan()

    async def _check_git_directory(self) -> bool:
        """Check if .git directory exists in the container."""
        cid = self.context.container_id
        if not cid:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "test -d /app/.git || test -d /src/.git || test -d /opt/.git",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _run_gitleaks(self) -> bool:
        """Run gitleaks for secret detection."""
        cid = self.context.container_id
        if not cid:
            return False

        # Check if gitleaks is available (host or container)
        try:
            proc = await asyncio.create_subprocess_exec(
                "gitleaks", "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False
        except (FileNotFoundError, OSError):
            return False

        # Find git root in container
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "cd /app && git rev-parse --show-toplevel 2>/dev/null || "
                "cd /src && git rev-parse --show-toplevel 2>/dev/null || "
                "echo /app",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            git_root = stdout.decode(errors="replace").strip().split("\n")[0]
        except Exception:
            git_root = "/app"

        # Run gitleaks
        try:
            report_path = "/tmp/gitleaks-report.json"
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "gitleaks", "detect",
                "--source", git_root,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            # Read report
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "cat", report_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return True  # gitleaks ran but no report

            output = stdout.decode(errors="replace")
            if not output.strip() or output.strip() == "[]":
                return True

            findings = json.loads(output)
            self._process_gitleaks_findings(findings)
            return True
        except (json.JSONDecodeError, Exception) as exc:
            logger.warning("Gitleaks execution failed: %s", exc)
            return True

    def _process_gitleaks_findings(self, findings: list[dict]) -> None:
        """Process gitleaks JSON findings."""
        # Deduplicate by secret value
        seen: set[str] = set()
        unique_findings: list[dict] = []

        for f in findings:
            secret = f.get("Secret", "")[:20]
            key = f"{f.get('RuleID', '')}:{secret}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        for f in unique_findings[:50]:
            rule_id = f.get("RuleID", "unknown")
            file_path = f.get("File", "")
            line = f.get("StartLine", 0)
            commit = f.get("Commit", "")[:8]
            author = f.get("Author", "")
            date = f.get("Date", "")
            description = f.get("Description", f"Secret type: {rule_id}")

            # Secrets in current HEAD are CRITICAL, historical are HIGH
            severity = Severity.CRITICAL if not commit else Severity.HIGH

            self.add_finding(
                title=f"Git secret: {rule_id} in {file_path}",
                description=(
                    f"Secret ({description}) found in git history. "
                    f"File: {file_path}, Line: {line}, "
                    f"Commit: {commit}, Author: {author}, Date: {date}."
                ),
                severity=severity,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Secret {rule_id} at {file_path}:{line}",
                        raw_data=f"Commit: {commit}\nFile: {file_path}\nLine: {line}",
                        location=file_path,
                    )
                ],
                remediation=(
                    "Rotate the exposed secret immediately. Remove it from git history "
                    "using git filter-repo or BFG Repo-Cleaner. Store secrets in a "
                    "secrets manager."
                ),
                cvss_score=9.0 if severity == Severity.CRITICAL else 7.0,
            )

    async def _run_builtin_scan(self) -> None:
        """Fallback: scan git log with built-in regex patterns."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "cd /app 2>/dev/null || cd /src 2>/dev/null; "
                "git log -p --all --max-count=100 2>/dev/null | head -50000",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return

            content = stdout.decode(errors="replace")
        except Exception:
            return

        if not content.strip():
            return

        # Scan with patterns
        all_hits: dict[str, list[str]] = {}
        for secret_type, pattern, severity in SECRET_PATTERNS:
            matches = list(pattern.finditer(content))
            if matches:
                unique = list({m.group()[:20] + "..." for m in matches[:5]})
                all_hits[secret_type] = unique

        if not all_hits:
            self.add_finding(
                title="No secrets found in git history (built-in scan)",
                description=(
                    "Built-in regex scanning of git log found no secrets. "
                    "Install gitleaks for more comprehensive scanning."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM01"],
                remediation="Install gitleaks for comprehensive git secret scanning.",
            )
            return

        for secret_type, matches in all_hits.items():
            severity = next(
                sev for name, _, sev in SECRET_PATTERNS if name == secret_type
            )
            self.add_finding(
                title=f"Git secret (built-in): {secret_type} ({len(matches)} unique)",
                description=(
                    f"Found {len(matches)} unique instance(s) of {secret_type} "
                    f"in git history using built-in scanning."
                ),
                severity=severity,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{secret_type} in git history",
                        raw_data="\n".join(matches[:5]),
                        location="git log",
                    )
                ],
                remediation=(
                    "Rotate exposed secrets immediately. Use git filter-repo to "
                    "remove from history. Install gitleaks for CI/CD integration."
                ),
                cvss_score=9.0 if severity == Severity.CRITICAL else 7.0,
            )
