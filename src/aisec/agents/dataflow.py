"""Data flow analysis agent -- PII, credentials, and encryption checks."""

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

# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    ),
    "phone_international": re.compile(
        r"\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[\s.-]?\d{4}[\s.-]?\d{4}[\s.-]?\d{1,4}\b"
    ),
    "argentine_dni": re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}\b"),
}

# ---------------------------------------------------------------------------
# Credential / secret patterns
# ---------------------------------------------------------------------------
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|auth_token|secret_key)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
    ),
    "private_key_header": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "password_assignment": re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"
    ),
    "bearer_token": re.compile(
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"
    ),
    "connection_string": re.compile(
        r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^\s'\"]{10,}"
    ),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{32,}"),
}

# Directories to scan inside the container
_SCAN_DIRS = "/app /src /opt /home /root /tmp /var/log"
# Extensions likely to contain source or config
_FILE_EXTENSIONS = (
    "*.py *.js *.ts *.json *.yaml *.yml *.toml *.ini *.cfg *.conf "
    "*.env *.sh *.bash *.txt *.md *.csv"
)


class DataFlowAgent(BaseAgent):
    """Inspect data flows for PII exposure, plaintext secrets, and
    missing encryption at rest."""

    name: ClassVar[str] = "dataflow"
    description: ClassVar[str] = (
        "Scans container files for PII patterns, plaintext credentials, "
        "and evaluates data-at-rest encryption."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM02", "ASI06"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run all data-flow checks."""
        file_contents = await self._collect_file_contents()
        if file_contents is None:
            logger.warning("Could not collect container files; skipping dataflow analysis")
            return

        await self._check_pii(file_contents)
        await self._check_credentials(file_contents)
        await self._check_encryption_at_rest()
        await self._check_unprotected_logs()

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    async def _collect_file_contents(self) -> dict[str, str] | None:
        """Gather text file contents from the container.

        Returns a dict mapping file path -> content (truncated).
        """
        cid = self.context.container_id
        if not cid:
            return None

        # Build a find command for relevant extensions
        ext_args = " -o ".join(f"-name '{e}'" for e in _FILE_EXTENSIONS.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            f"-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", find_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return None
            file_list = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return None

        if not file_list:
            return None

        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "65536", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    contents[fpath] = stdout.decode(errors="replace")
            except Exception:
                continue

        return contents if contents else None

    # ------------------------------------------------------------------
    # PII checks
    # ------------------------------------------------------------------

    async def _check_pii(self, files: dict[str, str]) -> None:
        """Scan file contents for PII patterns."""
        pii_hits: dict[str, list[tuple[str, str]]] = {}  # pattern -> [(file, match)]

        for fpath, content in files.items():
            for pii_name, regex in PII_PATTERNS.items():
                matches = regex.findall(content)
                if matches:
                    for m in matches[:5]:
                        pii_hits.setdefault(pii_name, []).append((fpath, str(m)))

        if not pii_hits:
            return

        for pii_name, hits in pii_hits.items():
            # Mask the actual values in evidence
            masked_examples = []
            for fpath, val in hits[:10]:
                masked = val[:3] + "***" + val[-2:] if len(val) > 5 else "***"
                masked_examples.append(f"  {fpath}: {masked}")

            self.add_finding(
                title=f"PII detected in container files: {pii_name}",
                description=(
                    f"Found {len(hits)} instance(s) of '{pii_name}' pattern in "
                    f"container files. Storing PII in plaintext violates data "
                    f"protection regulations and may lead to information disclosure "
                    f"if the AI agent's data is compromised."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MAP"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{pii_name} pattern matches ({len(hits)} hits)",
                        raw_data="\n".join(masked_examples),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Remove or encrypt PII data at rest. Implement data minimization "
                    "practices -- only store PII that is strictly necessary. Use "
                    "tokenization or pseudonymization for data the agent needs to "
                    "process. Ensure PII is not written to log files."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=6.5,
                ai_risk_score=7.0,
            )

    # ------------------------------------------------------------------
    # Credential / secret checks
    # ------------------------------------------------------------------

    async def _check_credentials(self, files: dict[str, str]) -> None:
        """Scan for plaintext credentials and API keys."""
        secret_hits: dict[str, list[tuple[str, str]]] = {}

        for fpath, content in files.items():
            for secret_name, regex in SECRET_PATTERNS.items():
                matches = regex.findall(content)
                if matches:
                    for m in matches[:3]:
                        secret_hits.setdefault(secret_name, []).append(
                            (fpath, str(m))
                        )

        # Also check environment variables set on the container
        env_secrets = await self._check_env_secrets()
        if env_secrets:
            secret_hits.setdefault("env_variable", []).extend(env_secrets)

        if not secret_hits:
            return

        for secret_name, hits in secret_hits.items():
            masked_examples = []
            for fpath, val in hits[:10]:
                masked = val[:4] + "****" if len(val) > 8 else "****"
                masked_examples.append(f"  {fpath}: {masked}")

            severity = Severity.CRITICAL if secret_name in (
                "aws_access_key", "aws_secret_key", "private_key_header",
                "openai_key", "github_token",
            ) else Severity.HIGH

            self.add_finding(
                title=f"Plaintext secret detected: {secret_name}",
                description=(
                    f"Found {len(hits)} instance(s) of '{secret_name}' in "
                    f"container files or environment variables. Hardcoded "
                    f"secrets can be extracted by an attacker who gains access "
                    f"to the container or its image layers."
                ),
                severity=severity,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{secret_name} ({len(hits)} occurrences)",
                        raw_data="\n".join(masked_examples),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Remove hardcoded secrets from source code and configuration "
                    "files. Use a secrets manager (e.g., HashiCorp Vault, AWS "
                    "Secrets Manager) or Docker secrets. Rotate any exposed "
                    "credentials immediately."
                ),
                cvss_score=9.0 if severity == Severity.CRITICAL else 7.5,
                ai_risk_score=8.0,
            )

    async def _check_env_secrets(self) -> list[tuple[str, str]]:
        """Check container environment variables for secrets."""
        cid = self.context.container_id
        if not cid:
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect",
                "--format", "{{json .Config.Env}}",
                cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            env_list = json.loads(stdout.decode(errors="replace"))
        except Exception:
            return []

        hits: list[tuple[str, str]] = []
        sensitive_keys = (
            "password", "secret", "token", "api_key", "apikey",
            "private_key", "access_key", "auth",
        )
        for env_str in env_list or []:
            if "=" not in env_str:
                continue
            key, _, value = env_str.partition("=")
            if any(s in key.lower() for s in sensitive_keys) and value:
                hits.append((f"ENV:{key}", value))

        return hits

    # ------------------------------------------------------------------
    # Encryption at rest
    # ------------------------------------------------------------------

    async def _check_encryption_at_rest(self) -> None:
        """Check whether data volumes use encryption."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect",
                "--format", "{{json .Mounts}}",
                cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return
            mounts = json.loads(stdout.decode(errors="replace"))
        except Exception:
            return

        if not mounts:
            return

        writable_mounts = [
            m for m in mounts
            if isinstance(m, dict) and not m.get("RW") is False
        ]

        if not writable_mounts:
            return

        # Docker does not natively encrypt volumes -- flag writable volumes
        mount_details = []
        for m in writable_mounts:
            src = m.get("Source", "unknown")
            dst = m.get("Destination", "unknown")
            mount_details.append(f"  {src} -> {dst}")

        self.add_finding(
            title="Writable volumes without verified encryption",
            description=(
                f"The container has {len(writable_mounts)} writable volume mount(s). "
                "Docker volumes are not encrypted by default. If the host filesystem "
                "is not using full-disk encryption, data written by the AI agent "
                "(including prompts, model outputs, and logs) may be stored in "
                "plaintext on disk."
            ),
            severity=Severity.MEDIUM,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN", "MANAGE"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"{len(writable_mounts)} writable volume(s)",
                    raw_data="\n".join(mount_details),
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Enable full-disk encryption (e.g., LUKS, FileVault, BitLocker) "
                "on the host. For sensitive workloads, use encrypted Docker "
                "volumes or application-level encryption for data at rest."
            ),
            cvss_score=4.0,
        )

    # ------------------------------------------------------------------
    # Unprotected logs
    # ------------------------------------------------------------------

    async def _check_unprotected_logs(self) -> None:
        """Check for log files that may contain sensitive data."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /var/log /tmp /app -maxdepth 4 -name '*.log' -type f -size +0 2>/dev/null | head -30",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            log_files = stdout.decode(errors="replace").strip().splitlines() if proc.returncode == 0 else []
        except Exception:
            log_files = []

        if not log_files:
            return

        # Sample log files for sensitive content
        sensitive_logs: list[tuple[str, str]] = []
        for log_path in log_files[:10]:
            log_path = log_path.strip()
            if not log_path:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "tail", "-c", "8192", log_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode != 0:
                    continue
                content = stdout.decode(errors="replace")
                for pii_name, regex in PII_PATTERNS.items():
                    if regex.search(content):
                        sensitive_logs.append((log_path, pii_name))
                        break
                for secret_name, regex in SECRET_PATTERNS.items():
                    if regex.search(content):
                        sensitive_logs.append((log_path, secret_name))
                        break
            except Exception:
                continue

        if sensitive_logs:
            details = "\n".join(f"  {f}: contains {t}" for f, t in sensitive_logs[:20])
            self.add_finding(
                title="Log files contain sensitive data",
                description=(
                    f"Found {len(sensitive_logs)} log file(s) containing PII or "
                    "secrets. Log files are frequently less protected than primary "
                    "data stores and may be exposed through log aggregation "
                    "systems, backups, or container image layers."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                evidence=[
                    Evidence(
                        type="log_entry",
                        summary="Logs with sensitive data",
                        raw_data=details,
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Implement log sanitization to redact PII and secrets before "
                    "writing to log files. Use structured logging with explicit "
                    "field filtering. Set appropriate file permissions and "
                    "rotation policies on log files."
                ),
                cvss_score=6.0,
                ai_risk_score=6.5,
            )
        elif log_files:
            # Check permissions on log files
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid,
                    "sh", "-c",
                    "ls -la " + " ".join(f.strip() for f in log_files[:10]) + " 2>/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                perms = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
            except Exception:
                perms = ""

            world_readable = [
                line for line in perms.splitlines()
                if line and len(line) > 10 and line[7] == "r"
            ]
            if world_readable:
                self.add_finding(
                    title="World-readable log files in container",
                    description=(
                        f"{len(world_readable)} log file(s) are world-readable. "
                        "Any process in the container can read these logs, which "
                        "may contain sensitive agent interactions."
                    ),
                    severity=Severity.LOW,
                    owasp_llm=["LLM02"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary="World-readable log files",
                            raw_data="\n".join(world_readable[:10]),
                            location=f"container:{cid}",
                        )
                    ],
                    remediation=(
                        "Set restrictive file permissions on log files (e.g., "
                        "chmod 640). Run the application as a non-root user with "
                        "a dedicated log group."
                    ),
                    cvss_score=3.0,
                )
