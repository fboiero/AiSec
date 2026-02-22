"""Data flow analysis agent -- PII, credentials, and encryption checks."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, ClassVar

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
        "and evaluates data-at-rest encryption. Optionally integrates with "
        "Microsoft Presidio for advanced PII detection and detect-secrets "
        "for entropy-based secret scanning when those libraries are installed."
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
        await self._check_pii_presidio(file_contents)
        await self._check_secrets_detect_secrets(file_contents)
        await self._check_encryption_at_rest()
        await self._check_unprotected_logs()
        await self._check_data_retention(file_contents)
        await self._check_database_credentials(file_contents)
        await self._check_backup_security()
        await self._check_data_flow_mapping()

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    def _exec_in_container(self, command: str) -> tuple[int, str]:
        """Execute a command in the target container via DockerManager or CLI."""
        dm = self.context.docker_manager
        if dm is not None:
            return dm.exec_in_target(command)
        return 1, ""

    async def _collect_file_contents(self) -> dict[str, str] | None:
        """Gather text file contents from the container.

        Returns a dict mapping file path -> content (truncated).
        """
        cid = self.context.container_id
        dm = self.context.docker_manager
        if not cid and dm is None:
            return None

        # Build a find command for relevant extensions
        ext_args = " -o ".join(f"-name '{e}'" for e in _FILE_EXTENSIONS.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            f"-size -1024k 2>/dev/null | head -200"
        )

        try:
            exit_code, output = await asyncio.to_thread(
                self._exec_in_container, f"sh -c {find_cmd!r}"
            )
            if exit_code != 0:
                return None
            file_list = output.strip().splitlines()
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
                exit_code, output = await asyncio.to_thread(
                    self._exec_in_container, f"head -c 65536 {fpath}"
                )
                if exit_code == 0:
                    contents[fpath] = output
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
    # PII checks -- Presidio (optional)
    # ------------------------------------------------------------------

    async def _check_pii_presidio(self, files: dict[str, str]) -> None:
        """Use Microsoft Presidio for advanced PII detection if installed.

        This is an optional enhancement that provides NLP-based PII
        recognition beyond the regex patterns in :meth:`_check_pii`.
        If ``presidio_analyzer`` is not installed the method returns
        silently so the agent continues to work with regex-only detection.
        """
        try:
            from presidio_analyzer import AnalyzerEngine, RecognizerResult  # noqa: F811
        except ImportError:
            logger.debug(
                "presidio_analyzer not installed -- skipping Presidio PII check. "
                "Install with: pip install presidio-analyzer"
            )
            return

        analyzer = AnalyzerEngine()

        # Aggregate results by entity type across all files
        entity_hits: dict[str, list[tuple[str, float, str]]] = {}
        # entity_type -> [(file, score, snippet)]

        for fpath, content in files.items():
            if not content.strip():
                continue
            try:
                results: list[RecognizerResult] = await asyncio.to_thread(
                    analyzer.analyze,
                    text=content,
                    language="en",
                )
            except Exception as exc:
                logger.debug("Presidio analysis failed for %s: %s", fpath, exc)
                continue

            for result in results:
                if result.score < 0.7:
                    continue
                snippet = content[result.start : result.end]
                entity_hits.setdefault(result.entity_type, []).append(
                    (fpath, result.score, snippet)
                )

        if not entity_hits:
            return

        for entity_type, hits in entity_hits.items():
            masked_examples = []
            for fpath, score, snippet in hits[:10]:
                if len(snippet) > 5:
                    masked = snippet[:3] + "***" + snippet[-2:]
                else:
                    masked = "***"
                masked_examples.append(
                    f"  {fpath}: {masked} (confidence: {score:.2f})"
                )

            self.add_finding(
                title=f"PII detected by Presidio: {entity_type}",
                description=(
                    f"Microsoft Presidio detected {len(hits)} high-confidence "
                    f"instance(s) of '{entity_type}' across container files. "
                    f"Presidio uses NLP-based recognition which can detect PII "
                    f"that simple regex patterns may miss, including names, "
                    f"addresses, and context-dependent identifiers."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MAP"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=(
                            f"Presidio {entity_type} detections "
                            f"({len(hits)} hits, score >= 0.7)"
                        ),
                        raw_data="\n".join(masked_examples),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Remove or encrypt PII data at rest. Implement data minimization "
                    "practices -- only store PII that is strictly necessary. Use "
                    "tokenization or pseudonymization for data the agent needs to "
                    "process. Consider integrating Presidio as a real-time data "
                    "sanitizer in your application's data pipeline."
                ),
                references=[
                    "https://microsoft.github.io/presidio/",
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

    def _get_inspect_data(self) -> dict[str, Any]:
        """Return docker inspect data via DockerManager."""
        dm = self.context.docker_manager
        if dm is not None:
            return dm.inspect_target()
        return {}

    async def _check_env_secrets(self) -> list[tuple[str, str]]:
        """Check container environment variables for secrets."""
        dm = self.context.docker_manager
        if dm is None and not self.context.container_id:
            return []

        try:
            info = await asyncio.to_thread(self._get_inspect_data)
            env_list = info.get("Config", {}).get("Env") or []
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
    # Secret checks -- detect-secrets (optional)
    # ------------------------------------------------------------------

    async def _check_secrets_detect_secrets(self, files: dict[str, str]) -> None:
        """Use detect-secrets for entropy-based secret scanning if installed.

        This is an optional enhancement that provides high-entropy string
        detection and plugin-based secret scanning beyond the regex patterns
        in :meth:`_check_credentials`.  If ``detect_secrets`` is not
        installed the method returns silently.
        """
        try:
            from detect_secrets import settings as ds_settings
            from detect_secrets.core.scan import scan_line
            from detect_secrets.settings import default_settings
        except ImportError:
            logger.debug(
                "detect-secrets not installed -- skipping entropy-based secret scan. "
                "Install with: pip install detect-secrets"
            )
            return

        secret_hits: list[tuple[str, str, str]] = []
        # (file, secret_type, masked_value)

        for fpath, content in files.items():
            if not content.strip():
                continue
            try:
                with default_settings():
                    for line_num, line in enumerate(content.splitlines(), start=1):
                        secrets = scan_line(fpath, line)
                        for secret in secrets:
                            secret_type = secret.type
                            # Mask the detected value
                            raw = line.strip()
                            if len(raw) > 8:
                                masked = raw[:4] + "****" + raw[-4:]
                            else:
                                masked = "****"
                            secret_hits.append((
                                f"{fpath}:{line_num}",
                                secret_type,
                                masked,
                            ))
            except Exception as exc:
                logger.debug("detect-secrets scan failed for %s: %s", fpath, exc)
                continue

        if not secret_hits:
            return

        # Group by secret type
        by_type: dict[str, list[tuple[str, str]]] = {}
        for location, secret_type, masked in secret_hits:
            by_type.setdefault(secret_type, []).append((location, masked))

        for secret_type, hits in by_type.items():
            details = "\n".join(
                f"  {loc}: {masked}" for loc, masked in hits[:10]
            )
            self.add_finding(
                title=f"Secret detected by detect-secrets: {secret_type}",
                description=(
                    f"The detect-secrets library identified {len(hits)} "
                    f"potential secret(s) of type '{secret_type}' in container "
                    f"files. detect-secrets uses entropy analysis and plugin-based "
                    f"heuristics to find secrets that pattern matching may miss, "
                    f"including high-entropy strings, base64-encoded tokens, and "
                    f"vendor-specific credential formats."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"detect-secrets: {secret_type} ({len(hits)} hits)",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Remove hardcoded secrets from source code and configuration "
                    "files. Use a secrets manager (e.g., HashiCorp Vault, AWS "
                    "Secrets Manager) or Docker secrets. Consider adding a "
                    "detect-secrets pre-commit hook to prevent secrets from "
                    "being committed to version control. Rotate any exposed "
                    "credentials immediately."
                ),
                references=[
                    "https://github.com/Yelp/detect-secrets",
                ],
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    # ------------------------------------------------------------------
    # Encryption at rest
    # ------------------------------------------------------------------

    async def _check_encryption_at_rest(self) -> None:
        """Check whether data volumes use encryption."""
        dm = self.context.docker_manager
        if dm is None and not self.context.container_id:
            return

        try:
            info = await asyncio.to_thread(self._get_inspect_data)
            mounts = info.get("Mounts") or []
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
        dm = self.context.docker_manager
        cid = self.context.container_id
        if dm is None and not cid:
            return

        find_cmd = "find /var/log /tmp /app -maxdepth 4 -name '*.log' -type f -size +0 2>/dev/null | head -30"
        try:
            exit_code, output = await asyncio.to_thread(
                self._exec_in_container, f"sh -c {find_cmd!r}"
            )
            log_files = output.strip().splitlines() if exit_code == 0 else []
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
                exit_code, content = await asyncio.to_thread(
                    self._exec_in_container, f"tail -c 8192 {log_path}"
                )
                if exit_code != 0:
                    continue
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
                ls_cmd = "ls -la " + " ".join(f.strip() for f in log_files[:10]) + " 2>/dev/null"
                exit_code, perms = await asyncio.to_thread(
                    self._exec_in_container, f"sh -c {ls_cmd!r}"
                )
                perms = perms.strip() if exit_code == 0 else ""
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

    # ------------------------------------------------------------------
    # Data retention policy checks
    # ------------------------------------------------------------------

    async def _check_data_retention(self, files: dict[str, str]) -> None:
        """Look for data retention policies in configuration files.

        Flags a finding if no retention, TTL, or expiry configuration is
        found, since AI agents that process personal or sensitive data
        without a retention policy risk regulatory violations.
        """
        retention_pattern = re.compile(
            r"(?i)(?:retention|ttl|expir[ey]|max[_\-]?age|purge|cleanup[_\-]?after"
            r"|delete[_\-]?after|keep[_\-]?days|log[_\-]?rotation)",
        )

        config_extensions = (".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".json", ".env")

        retention_found: list[tuple[str, str]] = []
        for fpath, content in files.items():
            if any(fpath.endswith(ext) for ext in config_extensions):
                matches = retention_pattern.findall(content)
                if matches:
                    for m in matches[:3]:
                        retention_found.append((fpath, m))

        if retention_found:
            return

        # No retention policy detected -- raise a finding
        config_files_scanned = [
            f for f in files if any(f.endswith(ext) for ext in config_extensions)
        ]

        self.add_finding(
            title="No data retention policy detected",
            description=(
                f"Scanned {len(config_files_scanned)} configuration file(s) in the "
                "container but found no retention, TTL, or expiry settings. "
                "AI agents that store conversation history, user data, or model "
                "outputs without a defined retention policy may violate GDPR, "
                "CCPA, and other data protection regulations."
            ),
            severity=Severity.MEDIUM,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"No retention config in {len(config_files_scanned)} config files",
                    raw_data=(
                        "Config files scanned:\n"
                        + "\n".join(f"  {f}" for f in config_files_scanned[:20])
                        if config_files_scanned
                        else "No configuration files found in container."
                    ),
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Define explicit data retention policies in application configuration. "
                "Set TTL values for stored conversations, logs, and model outputs. "
                "Implement automated data purging to remove expired records. "
                "Document the retention schedule and ensure compliance with applicable "
                "data protection regulations."
            ),
            cvss_score=4.0,
            ai_risk_score=6.0,
        )

    # ------------------------------------------------------------------
    # Database credential checks
    # ------------------------------------------------------------------

    async def _check_database_credentials(self, files: dict[str, str]) -> None:
        """Scan for database connection strings in files and env vars.

        Uses the ``database_url`` pattern to detect connection strings
        that embed credentials (e.g. ``postgres://user:pass@host/db``).
        """
        db_url_pattern = re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^\s'\"]{10,}"
        )

        db_hits: list[tuple[str, str]] = []

        # Scan file contents
        for fpath, content in files.items():
            matches = db_url_pattern.findall(content)
            for m in matches[:3]:
                db_hits.append((fpath, str(m)))

        # Scan environment variables via DockerManager
        dm = self.context.docker_manager
        if dm is not None:
            try:
                info = await asyncio.to_thread(self._get_inspect_data)
                env_list = info.get("Config", {}).get("Env") or []
                for env_str in env_list:
                    if "=" not in env_str:
                        continue
                    key, _, value = env_str.partition("=")
                    if db_url_pattern.search(value):
                        db_hits.append((f"ENV:{key}", value))
            except Exception:
                pass

        if not db_hits:
            return

        masked_examples = []
        for source, url in db_hits[:10]:
            # Mask credentials in the URL (user:pass portion)
            masked_url = re.sub(
                r"(://)[^@]+(@)", r"\1****:****\2", url
            )
            if len(masked_url) > 80:
                masked_url = masked_url[:80] + "..."
            masked_examples.append(f"  {source}: {masked_url}")

        self.add_finding(
            title="Database connection string with embedded credentials",
            description=(
                f"Found {len(db_hits)} database connection string(s) containing "
                "embedded credentials. Connection strings with plaintext "
                "usernames and passwords can be extracted from container "
                "files, environment variables, or image layers, granting "
                "direct access to backend databases."
            ),
            severity=Severity.CRITICAL,
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["GOVERN"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Database URLs with credentials ({len(db_hits)} hits)",
                    raw_data="\n".join(masked_examples),
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Remove database credentials from connection strings and "
                "configuration files. Use a secrets manager or IAM-based "
                "authentication instead of password-based connections. "
                "If environment variables must be used, inject them at "
                "runtime via Docker secrets or orchestrator secret stores. "
                "Rotate any exposed database credentials immediately."
            ),
            cvss_score=9.0,
            ai_risk_score=8.5,
        )

    # ------------------------------------------------------------------
    # Backup security checks
    # ------------------------------------------------------------------

    async def _check_backup_security(self) -> None:
        """Look for backup files in the container and flag unencrypted ones.

        Searches for common backup extensions (.bak, .dump, .sql, .tar.gz)
        and checks whether they appear to be encrypted.
        """
        dm = self.context.docker_manager
        cid = self.context.container_id
        if dm is None and not cid:
            return

        backup_extensions = "*.bak *.dump *.sql *.tar.gz *.sql.gz *.bak.gz *.backup"
        ext_args = " -o ".join(f"-name '{e}'" for e in backup_extensions.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            f"-size +0 2>/dev/null | head -50"
        )

        try:
            exit_code, output = await asyncio.to_thread(
                self._exec_in_container, f"sh -c {find_cmd!r}"
            )
            if exit_code != 0:
                return
            backup_files = output.strip().splitlines()
        except Exception:
            return

        if not backup_files:
            return

        # Check each backup file for encryption indicators
        unencrypted: list[tuple[str, str]] = []
        for bfile in backup_files[:20]:
            bfile = bfile.strip()
            if not bfile:
                continue
            try:
                # Read first 16 bytes to check for encryption magic bytes
                header_cmd = f"head -c 16 '{bfile}' | od -A x -t x1z -N 16 2>/dev/null"
                exit_code, header = await asyncio.to_thread(
                    self._exec_in_container, f"sh -c {header_cmd!r}"
                )
                header = header.strip() if exit_code == 0 else ""

                # Get file size
                ls_cmd = f"ls -lh '{bfile}' 2>/dev/null"
                exit_code, file_info = await asyncio.to_thread(
                    self._exec_in_container, f"sh -c {ls_cmd!r}"
                )
                file_info = file_info.strip() if exit_code == 0 else ""

                # GPG/PGP encrypted files start with specific magic bytes;
                # if we do not see them, treat the file as unencrypted.
                is_encrypted = False
                if header:
                    # GPG binary: 0x8c, 0xa3, 0xc6 or ASCII-armored starts with "---"
                    if any(marker in header for marker in ("8c", "a3", "c6")):
                        is_encrypted = True

                if not is_encrypted:
                    size_str = file_info.split()[4] if len(file_info.split()) > 4 else "unknown"
                    unencrypted.append((bfile, size_str))

            except Exception:
                unencrypted.append((bfile, "unknown"))
                continue

        if not unencrypted:
            return

        details = "\n".join(f"  {f} (size: {s})" for f, s in unencrypted[:20])

        self.add_finding(
            title="Unencrypted backup files found in container",
            description=(
                f"Found {len(unencrypted)} backup file(s) in the container that "
                "do not appear to be encrypted. Backup files may contain "
                "database dumps, application state, or model data that "
                "could be exfiltrated if the container is compromised."
            ),
            severity=Severity.HIGH,
            owasp_llm=["LLM02"],
            nist_ai_rmf=["GOVERN"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"{len(unencrypted)} unencrypted backup file(s)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Encrypt all backup files using GPG, age, or another strong "
                "encryption tool before storing them in the container or on "
                "mounted volumes. Ideally, backups should not reside inside "
                "running containers at all -- store them in a dedicated, "
                "access-controlled backup system with encryption at rest."
            ),
            cvss_score=6.5,
            ai_risk_score=7.0,
        )

    # ------------------------------------------------------------------
    # Data flow mapping
    # ------------------------------------------------------------------

    async def _check_data_flow_mapping(self) -> None:
        """Generate a data flow map from environment variables.

        Inspects container environment variables for external connection
        endpoints (API URLs, database hosts, message queues) and produces
        a Mermaid diagram summarizing the data flows.
        """
        cid = self.context.container_id
        dm = self.context.docker_manager
        if dm is None and not cid:
            return

        try:
            info = await asyncio.to_thread(self._get_inspect_data)
            env_list = info.get("Config", {}).get("Env") or []
        except Exception:
            return

        if not env_list:
            return

        # Patterns to detect external connections
        url_pattern = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
        db_pattern = re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb|redis|amqp)://[^\s'\"]+",
        )
        host_keys = (
            "host", "hostname", "endpoint", "server", "broker",
            "queue", "url", "uri", "dsn", "addr",
        )

        connections: list[dict[str, str]] = []
        for env_str in env_list or []:
            if "=" not in env_str:
                continue
            key, _, value = env_str.partition("=")
            if not value:
                continue

            # Database connections
            db_match = db_pattern.search(value)
            if db_match:
                # Extract scheme and host, masking credentials
                masked = re.sub(r"(://)[^@]*@", r"\1***@", db_match.group())
                connections.append({
                    "env_var": key,
                    "type": "database",
                    "target": masked,
                })
                continue

            # HTTP/HTTPS URLs
            url_match = url_pattern.search(value)
            if url_match:
                connections.append({
                    "env_var": key,
                    "type": "api",
                    "target": url_match.group()[:120],
                })
                continue

            # Host-like keys
            if any(h in key.lower() for h in host_keys):
                connections.append({
                    "env_var": key,
                    "type": "service",
                    "target": value[:120],
                })

        if not connections:
            return

        # Build Mermaid diagram
        mermaid_lines = ["graph LR", f"    Container[\"{cid[:12]}...\"]"]
        seen_targets: set[str] = set()

        for i, conn in enumerate(connections[:25]):
            target_label = conn["target"]
            if len(target_label) > 60:
                target_label = target_label[:57] + "..."
            node_id = f"ext{i}"

            # Determine node shape by type
            if conn["type"] == "database":
                node_def = f"    {node_id}[(\"{target_label}\")]"
            elif conn["type"] == "api":
                node_def = f"    {node_id}[\"{target_label}\"]"
            else:
                node_def = f"    {node_id}([\"{target_label}\"])"

            edge_label = conn["env_var"]
            if len(edge_label) > 30:
                edge_label = edge_label[:27] + "..."

            target_key = f"{conn['type']}:{conn['target']}"
            if target_key not in seen_targets:
                seen_targets.add(target_key)
                mermaid_lines.append(node_def)
                mermaid_lines.append(
                    f"    Container -->|{edge_label}| {node_id}"
                )

        mermaid_diagram = "\n".join(mermaid_lines)

        # Store the data flow map as an informational finding
        self.add_finding(
            title="Data flow map generated from container environment",
            description=(
                f"Identified {len(connections)} external connection(s) configured "
                "via environment variables. This data flow map shows how the "
                "AI agent communicates with external services, databases, and "
                "APIs. Review the connections to ensure all data flows are "
                "authorized, encrypted in transit, and aligned with the "
                "system's intended architecture."
            ),
            severity=Severity.INFO,
            nist_ai_rmf=["MAP"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"Data flow map ({len(connections)} connections)",
                    raw_data=mermaid_diagram,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Review the data flow map to verify all external connections are "
                "intentional and documented. Ensure all connections use TLS/SSL. "
                "Remove any unnecessary external service dependencies. Document "
                "the expected data flows as part of the system's security architecture."
            ),
            cvss_score=0.0,
            ai_risk_score=3.0,
        )
