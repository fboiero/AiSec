"""PII data lineage and privacy compliance agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# PII field/variable name patterns
PII_VAR_PATTERNS = re.compile(
    r'(?:email|first_name|last_name|full_name|phone|ssn|social_security|'
    r'date_of_birth|dob|address|zip_code|postal|credit_card|card_number|'
    r'passport|national_id|health_record|medical|diagnosis|patient|'
    r'user_name|username|user_id|ip_address|location|gender|ethnicity|'
    r'salary|income|bank_account|iban|tax_id|driver_license)',
    re.IGNORECASE,
)

# LLM API call patterns
LLM_API_PATTERNS = re.compile(
    r'(?:openai\.(?:ChatCompletion|Completion)|client\.chat\.completions\.create|'
    r'anthropic\.(?:messages|completions)|client\.messages\.create|'
    r'langchain.*(?:llm|chain|agent)\.(?:run|invoke|predict|call)|'
    r'huggingface.*(?:pipeline|model)\(|'
    r'cohere\.generate|replicate\.run|'
    r'completion\s*=\s*.*(?:openai|anthropic|llm))',
    re.IGNORECASE,
)

# Anonymization/pseudonymization patterns
ANONYMIZATION_PATTERNS = re.compile(
    r'(?:anonymize|pseudonymize|mask|redact|hash_pii|scrub|sanitize_pii|'
    r'remove_pii|deidentify|de_identify|privacy_filter|pii_filter|'
    r'presidio|piiranha|data_masking)',
    re.IGNORECASE,
)

# Consent mechanism patterns
CONSENT_PATTERNS = re.compile(
    r'(?:consent|gdpr_consent|user_consent|data_consent|privacy_consent|'
    r'opt_in|opt_out|cookie_consent|data_processing_agreement|'
    r'terms_accepted|privacy_accepted|consent_given|has_consent)',
    re.IGNORECASE,
)

# Data deletion patterns
DELETION_PATTERNS = re.compile(
    r'(?:delete_user|remove_user|erase_user|purge_user|forget_user|'
    r'right_to_erasure|data_deletion|gdpr_delete|remove_personal|'
    r'anonymize_user|user\.delete|\.delete\(\).*user|'
    r'delete_account|account_deletion|remove_account)',
    re.IGNORECASE,
)

# Logging PII patterns
LOG_PII_PATTERNS = re.compile(
    r'(?:log(?:ger)?\.(?:info|debug|warning|error|critical)|print|logging\.)'
    r'[^;]*(?:email|password|ssn|credit_card|phone|name|address|token|secret)',
    re.IGNORECASE,
)

# Fine-tuning data patterns
FINETUNE_PATTERNS = re.compile(
    r'(?:fine_tune|finetune|training_data|train_data|prepare_training|'
    r'jsonl.*train|dataset.*train|openai\.FineTuningJob|'
    r'TrainingArguments|Trainer\()',
    re.IGNORECASE,
)


class DataLineagePrivacyAgent(BaseAgent):
    """Tracks PII data lineage and privacy compliance."""

    name: ClassVar[str] = "data_lineage"
    description: ClassVar[str] = (
        "Tracks PII data flows to LLM APIs, verifies consent mechanisms, "
        "checks right-to-erasure implementation, detects PII in logs, "
        "and maps findings to GDPR/CCPA requirements."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM06", "ASI06", "ASI07"]
    depends_on: ClassVar[list[str]] = ["dataflow", "privacy"]

    async def analyze(self) -> None:
        """Run privacy and data lineage analysis."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for data lineage analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        self._check_pii_to_llm(all_content, combined)
        self._check_consent_mechanism(combined)
        self._check_erasure_mechanism(combined)
        self._check_pii_in_logs(all_content)
        self._check_training_data_privacy(all_content, combined)
        self._check_pii_audit_trail(combined)

    def _check_pii_to_llm(self, files: dict[str, str], combined: str) -> None:
        """Check if PII variables are sent to LLM API calls."""
        has_llm_calls = bool(LLM_API_PATTERNS.search(combined))
        has_pii = bool(PII_VAR_PATTERNS.search(combined))
        has_anonymization = bool(ANONYMIZATION_PATTERNS.search(combined))

        if not has_llm_calls or not has_pii:
            return

        # Look for files that have both PII variables and LLM calls
        pii_llm_files: list[tuple[str, list[str], list[str]]] = []

        for fpath, content in files.items():
            pii_matches = list(PII_VAR_PATTERNS.finditer(content))
            llm_matches = list(LLM_API_PATTERNS.finditer(content))

            if pii_matches and llm_matches:
                pii_vars = list({m.group()[:30] for m in pii_matches[:5]})
                llm_calls = list({m.group()[:40] for m in llm_matches[:5]})
                pii_llm_files.append((fpath, pii_vars, llm_calls))

        if not pii_llm_files:
            return

        severity = Severity.MEDIUM if has_anonymization else Severity.HIGH

        details = "\n".join(
            f"  {f}: PII={', '.join(pvars[:3])}, LLM={', '.join(calls[:2])}"
            for f, pvars, calls in pii_llm_files[:10]
        )

        self.add_finding(
            title=f"PII data sent to LLM APIs ({len(pii_llm_files)} files)",
            description=(
                f"Found {len(pii_llm_files)} file(s) where PII variables and LLM API "
                f"calls coexist. {'Anonymization patterns detected but verify coverage.' if has_anonymization else 'No anonymization/pseudonymization patterns detected.'} "
                "Sending PII to LLM APIs may violate GDPR Art. 5(1)(c) (data minimization) "
                "and CCPA requirements."
            ),
            severity=severity,
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN", "MAP"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="PII variables near LLM API calls",
                    raw_data=details,
                    location=pii_llm_files[0][0] if pii_llm_files else "",
                )
            ],
            remediation=(
                "Anonymize or pseudonymize PII before sending to LLM APIs. "
                "Use tools like Presidio or PIIranha for automated PII redaction. "
                "Implement data minimization: only send necessary data to LLMs."
            ),
            cvss_score=6.0 if has_anonymization else 7.5,
            ai_risk_score=8.0,
        )

    def _check_consent_mechanism(self, combined: str) -> None:
        """Check for consent collection mechanisms."""
        has_pii = bool(PII_VAR_PATTERNS.search(combined))
        has_consent = bool(CONSENT_PATTERNS.search(combined))

        if has_pii and not has_consent:
            self.add_finding(
                title="No consent mechanism for PII processing",
                description=(
                    "PII processing detected but no consent mechanism found. "
                    "GDPR Art. 6 requires a lawful basis for processing personal data, "
                    "and CCPA requires notice at collection."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Implement consent collection before PII processing. Include "
                    "opt-in/opt-out mechanisms. Document lawful basis for processing "
                    "under GDPR Art. 6."
                ),
                cvss_score=5.0,
                ai_risk_score=7.0,
            )

    def _check_erasure_mechanism(self, combined: str) -> None:
        """Check for right-to-erasure (GDPR Art. 17) implementation."""
        has_pii = bool(PII_VAR_PATTERNS.search(combined))
        has_deletion = bool(DELETION_PATTERNS.search(combined))

        if has_pii and not has_deletion:
            self.add_finding(
                title="No right-to-erasure implementation",
                description=(
                    "PII processing detected but no user deletion/erasure mechanism "
                    "found. GDPR Art. 17 (Right to Erasure) requires the ability to "
                    "delete personal data upon request. CCPA provides similar rights."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Implement a user data deletion function that removes all PII. "
                    "Ensure deletion cascades to all storage systems including logs, "
                    "caches, backups, and LLM fine-tuning datasets."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_pii_in_logs(self, files: dict[str, str]) -> None:
        """Check for PII in log statements."""
        log_pii_files: list[tuple[str, int]] = []

        for fpath, content in files.items():
            matches = list(LOG_PII_PATTERNS.finditer(content))
            if matches:
                log_pii_files.append((fpath, len(matches)))

        if log_pii_files:
            total = sum(count for _, count in log_pii_files)
            details = "\n".join(
                f"  {f}: {count} instances" for f, count in log_pii_files[:10]
            )
            self.add_finding(
                title=f"PII in log statements ({total} instances in {len(log_pii_files)} files)",
                description=(
                    f"Found {total} log statement(s) potentially containing PII "
                    f"across {len(log_pii_files)} files. PII in logs violates "
                    "GDPR Art. 5(1)(e) (storage limitation) and makes erasure "
                    "requests difficult to fulfill."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="PII in logs",
                        raw_data=details,
                        location=log_pii_files[0][0] if log_pii_files else "",
                    )
                ],
                remediation=(
                    "Redact PII from log statements. Use structured logging with "
                    "PII filtering. Set log retention policies with automatic rotation."
                ),
                cvss_score=4.0,
            )

    def _check_training_data_privacy(self, files: dict[str, str], combined: str) -> None:
        """Check for user data in fine-tuning without consent."""
        has_finetune = bool(FINETUNE_PATTERNS.search(combined))
        has_pii = bool(PII_VAR_PATTERNS.search(combined))
        has_consent = bool(CONSENT_PATTERNS.search(combined))

        if has_finetune and has_pii:
            severity = Severity.MEDIUM if has_consent else Severity.HIGH
            self.add_finding(
                title="User PII in training/fine-tuning pipeline",
                description=(
                    "Fine-tuning code detected alongside PII handling. "
                    f"{'Consent mechanisms exist but verify training data is explicitly consented.' if has_consent else 'No consent mechanism found for training data usage.'} "
                    "Using personal data for model training without explicit consent "
                    "violates GDPR Art. 6 and Art. 13."
                ),
                severity=severity,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MAP"],
                remediation=(
                    "Obtain explicit consent for using personal data in training. "
                    "Implement data deduplication and PII scrubbing in the training pipeline. "
                    "Document the training data processing in your privacy policy."
                ),
                cvss_score=6.0,
                ai_risk_score=7.0,
            )

    def _check_pii_audit_trail(self, combined: str) -> None:
        """Check for PII access audit trail."""
        has_pii = bool(PII_VAR_PATTERNS.search(combined))

        audit_pattern = re.compile(
            r'(?:audit_log|access_log|pii_access|data_access_log|'
            r'log_pii_access|track_access|audit_trail|gdpr_log)',
            re.IGNORECASE,
        )
        has_audit = bool(audit_pattern.search(combined))

        if has_pii and not has_audit:
            self.add_finding(
                title="No PII access audit trail",
                description=(
                    "PII processing detected but no audit trail for PII access. "
                    "GDPR Art. 30 requires records of processing activities, and "
                    "audit trails are essential for demonstrating compliance."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Implement audit logging for all PII access and modifications. "
                    "Log who accessed what data, when, and for what purpose."
                ),
                cvss_score=3.0,
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
