"""Privacy compliance analysis agent -- GDPR, CCPA, Habeas Data."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, CheckStatus, Severity
from aisec.core.models import ComplianceCheckItem, Evidence

logger = logging.getLogger(__name__)


class PrivacyAgent(BaseAgent):
    """Evaluate compliance with GDPR, CCPA, and Argentine Habeas Data law."""

    name: ClassVar[str] = "privacy"
    description: ClassVar[str] = (
        "Assesses the AI agent container for compliance with major data "
        "protection regulations: GDPR (EU), CCPA (California), and "
        "Habeas Data (Argentina)."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.POST
    frameworks: ClassVar[list[str]] = ["LLM02"]
    depends_on: ClassVar[list[str]] = ["dataflow"]

    async def analyze(self) -> None:
        """Run compliance checks against each framework."""
        # Pull findings from the dataflow agent to inform compliance checks
        dataflow_result = self.context.agent_results.get("dataflow")
        dataflow_findings = dataflow_result.findings if dataflow_result else []
        has_pii = any("PII" in f.title for f in dataflow_findings)
        has_secrets = any("secret" in f.title.lower() or "credential" in f.title.lower() for f in dataflow_findings)
        has_log_issues = any("log" in f.title.lower() for f in dataflow_findings)

        container_info = await self._get_container_env()

        await self._check_gdpr(has_pii, has_secrets, has_log_issues, container_info)
        await self._check_ccpa(has_pii, has_secrets, has_log_issues, container_info)
        await self._check_habeas_data(has_pii, has_secrets, has_log_issues, container_info)
        await self._check_anonymization(has_pii, container_info)

    # ------------------------------------------------------------------
    # Container env helper
    # ------------------------------------------------------------------

    async def _get_container_env(self) -> dict[str, str]:
        """Fetch environment variables from the container as a dict."""
        cid = self.context.container_id
        if not cid:
            return {}
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
                return {}
            env_list = json.loads(stdout.decode(errors="replace")) or []
            return {
                k: v
                for item in env_list
                if "=" in item
                for k, _, v in [item.partition("=")]
            }
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Privacy-specific file probing
    # ------------------------------------------------------------------

    async def _probe_file_exists(self, *paths: str) -> list[str]:
        """Check which paths exist inside the container."""
        cid = self.context.container_id
        if not cid:
            return []
        found: list[str] = []
        for p in paths:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "test", "-e", p,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                if proc.returncode == 0:
                    found.append(p)
            except Exception:
                continue
        return found

    async def _grep_container(self, pattern: str) -> str:
        """Run a grep inside the container returning first matches."""
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                f"grep -r -i -l '{pattern}' /app /src /opt 2>/dev/null | head -10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Data anonymization verification (M2.4)
    # ------------------------------------------------------------------

    async def _check_anonymization(
        self,
        has_pii: bool,
        env: dict[str, str],
    ) -> None:
        """Data anonymization verification checks.

        Implements M2.4 from the project plan. Verifies that proper
        anonymization and pseudonymization techniques are applied to
        protect personal data processed by the AI agent.
        """

        # ----------------------------------------------------------
        # 1. Anonymization / pseudonymization implementation
        # ----------------------------------------------------------
        anon_patterns = (
            "anonymi\\|pseudonymi\\|hash_pii\\|mask_pii"
            "\\|tokenize\\|k.anonymity\\|differential.privacy\\|faker"
        )
        anon_refs = await self._grep_container(anon_patterns)

        if not anon_refs and has_pii:
            self.add_finding(
                title="No anonymization or pseudonymization implementation detected",
                description=(
                    "The container processes PII but no anonymization or "
                    "pseudonymization mechanisms were found. Data protection "
                    "regulations (GDPR Art. 25, CCPA) recommend or require "
                    "pseudonymization as a safeguard. Common techniques "
                    "include hashing, tokenization, k-anonymity, "
                    "differential privacy, and data masking."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MAP", "MANAGE"],
                evidence=[
                    Evidence(
                        type="code",
                        summary="No anonymization patterns found in container source",
                        raw_data=(
                            f"Searched patterns: {anon_patterns}\n"
                            "Matching files: none\n"
                            "PII detected by dataflow agent: True"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement data anonymization or pseudonymization before "
                    "processing PII. Consider using libraries such as Faker "
                    "(synthetic data), Microsoft Presidio (PII detection and "
                    "anonymization), or ARX (k-anonymity / l-diversity). Apply "
                    "pseudonymization at the ingestion boundary so that "
                    "downstream components never see raw identifiers."
                ),
                references=[
                    "https://gdpr.eu/recital-26-not-applicable-to-anonymous-data/",
                    "https://microsoft.github.io/presidio/",
                    "https://arx.deidentifier.org/",
                ],
                cvss_score=6.5,
                ai_risk_score=8.0,
            )

        # ----------------------------------------------------------
        # 2. Re-identification risk (quasi-identifiers)
        # ----------------------------------------------------------
        quasi_patterns = (
            "zip.code\\|postal.code\\|birth.date\\|date.of.birth\\|dob"
            "\\|gender\\|age\\|ethnicity\\|nationality"
        )
        quasi_refs = await self._grep_container(quasi_patterns)

        # Check if multiple quasi-identifiers appear together
        qi_files = [f.strip() for f in quasi_refs.splitlines() if f.strip()] if quasi_refs else []
        # A file containing multiple quasi-identifiers is a higher risk
        multi_qi = len(qi_files) >= 2

        if quasi_refs and has_pii:
            self.add_finding(
                title="Re-identification risk: quasi-identifiers detected alongside PII",
                description=(
                    "The container references quasi-identifiers (e.g., zip code, "
                    "birth date, gender) in combination with PII. Research by "
                    "Latanya Sweeney demonstrated that 87% of the US population "
                    "can be uniquely identified using only zip code, birth date, "
                    "and gender. The presence of multiple quasi-identifiers "
                    "significantly increases the risk of re-identification even "
                    "when direct identifiers are removed."
                ),
                severity=Severity.HIGH if multi_qi else Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["MAP", "MEASURE"],
                evidence=[
                    Evidence(
                        type="code",
                        summary=(
                            f"Quasi-identifier references found in {len(qi_files)} file(s)"
                        ),
                        raw_data=(
                            f"Searched patterns: {quasi_patterns}\n"
                            f"Matching files:\n{quasi_refs[:800]}"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Apply generalization or suppression to quasi-identifiers "
                    "before processing. For example, generalize zip codes to "
                    "the first 3 digits, replace exact birth dates with age "
                    "ranges, and aggregate gender into broader categories. "
                    "Implement k-anonymity (k >= 5) or l-diversity to ensure "
                    "that no individual can be singled out from the dataset."
                ),
                references=[
                    "https://dataprivacylab.org/projects/identifiability/",
                    "https://en.wikipedia.org/wiki/Quasi-identifier",
                    "https://doi.org/10.1142/S0218488502001648",
                ],
                cvss_score=5.5,
                ai_risk_score=7.5,
            )

        # ----------------------------------------------------------
        # 3. k-Anonymity assessment
        # ----------------------------------------------------------
        kanon_refs = await self._grep_container(
            "k.anonymity\\|l.diversity\\|t.closeness\\|kanonymity\\|KAnonymity"
        )

        if not kanon_refs and has_pii:
            self.add_finding(
                title="No k-anonymity or equivalent privacy model implemented",
                description=(
                    "The container processes PII but does not implement "
                    "k-anonymity, l-diversity, t-closeness, or any equivalent "
                    "formal privacy model. Without such models, released or "
                    "processed datasets may allow statistical re-identification "
                    "of individuals. k-anonymity ensures that each combination "
                    "of quasi-identifiers maps to at least k records, making "
                    "it harder to single out individuals."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["MAP", "MEASURE", "MANAGE"],
                evidence=[
                    Evidence(
                        type="code",
                        summary="No k-anonymity / l-diversity / t-closeness patterns found",
                        raw_data=(
                            "Searched for: k.anonymity, l.diversity, t.closeness, "
                            "kanonymity, KAnonymity\n"
                            "Matching files: none"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement a formal privacy model before releasing or "
                    "processing datasets containing personal information. "
                    "Use libraries such as ARX Data Anonymization Tool, "
                    "Google's differential-privacy library, or the Python "
                    "'anonymeter' package. Target at least k=5 for "
                    "k-anonymity and complement with l-diversity to protect "
                    "against attribute-disclosure attacks."
                ),
                references=[
                    "https://arx.deidentifier.org/",
                    "https://github.com/google/differential-privacy",
                    "https://doi.org/10.1007/s10207-006-0032-z",
                ],
                cvss_score=4.5,
                ai_risk_score=6.5,
            )

        # ----------------------------------------------------------
        # 4. Data masking in logs
        # ----------------------------------------------------------
        pii_log_patterns = (
            "email\\|password\\|ssn\\|social.security\\|credit.card"
            "\\|phone.number\\|address"
        )
        log_paths = [
            "/var/log",
            "/app/logs",
            "/app/log",
            "/tmp/*.log",
            "/opt/app/logs",
        ]
        log_dirs_found = await self._probe_file_exists(*log_paths)

        # If log directories exist, search for PII patterns inside them
        pii_in_logs = ""
        if log_dirs_found:
            cid = self.context.container_id
            if cid:
                try:
                    dirs_str = " ".join(log_dirs_found)
                    proc = await asyncio.create_subprocess_exec(
                        "docker", "exec", cid,
                        "sh", "-c",
                        f"grep -r -i -l '{pii_log_patterns}' {dirs_str} 2>/dev/null | head -10",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    pii_in_logs = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
                except Exception:
                    pii_in_logs = ""

        if pii_in_logs:
            self.add_finding(
                title="PII patterns detected in log files -- data masking absent",
                description=(
                    "Log files inside the container contain patterns that match "
                    "common PII fields (email, password, SSN, credit card, "
                    "phone number, address). Logs are frequently collected by "
                    "centralized logging systems and may be accessible to "
                    "operations staff who should not have access to personal "
                    "data. GDPR Art. 25 and CCPA Sec. 1798.150 require "
                    "appropriate technical measures to protect personal data."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="file",
                        summary="Log files containing PII patterns",
                        raw_data=(
                            f"Log directories checked: {', '.join(log_dirs_found)}\n"
                            f"Files with PII patterns:\n{pii_in_logs[:800]}"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement structured logging with automatic PII redaction. "
                    "Use a log formatter that masks sensitive fields before "
                    "writing to disk or forwarding to a log aggregator. "
                    "Libraries such as 'loguru' (with custom sinks) or custom "
                    "Python logging.Filter subclasses can redact PII patterns. "
                    "Never log raw request/response bodies that may contain "
                    "personal data."
                ),
                references=[
                    "https://owasp.org/www-project-logging-cheat-sheet/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                ],
                cvss_score=6.0,
                ai_risk_score=7.5,
            )

        # ----------------------------------------------------------
        # 5. PII in caches and temporary files
        # ----------------------------------------------------------
        temp_paths = [
            "/tmp",
            "/var/tmp",
            "/var/cache",
            "/dev/shm",
            "/app/.cache",
            "/root/.cache",
        ]
        temp_dirs_found = await self._probe_file_exists(*temp_paths)

        pii_in_temp = ""
        if temp_dirs_found:
            cid = self.context.container_id
            if cid:
                try:
                    dirs_str = " ".join(temp_dirs_found)
                    proc = await asyncio.create_subprocess_exec(
                        "docker", "exec", cid,
                        "sh", "-c",
                        (
                            f"find {dirs_str} -type f -size +0 2>/dev/null | head -20 | "
                            f"xargs grep -l -i '{pii_log_patterns}' 2>/dev/null | head -10"
                        ),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    pii_in_temp = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
                except Exception:
                    pii_in_temp = ""

        if pii_in_temp:
            self.add_finding(
                title="PII detected in temporary files or caches",
                description=(
                    "Temporary directories or caches inside the container hold "
                    "files that match PII patterns. Temporary files are often "
                    "world-readable, survive container restarts when volumes "
                    "are mounted, and may be included in container image layers "
                    "if the Dockerfile does not clean them up. This creates an "
                    "uncontrolled copy of personal data outside the primary "
                    "data store."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="file",
                        summary="Temp/cache files containing PII patterns",
                        raw_data=(
                            f"Temp directories checked: {', '.join(temp_dirs_found)}\n"
                            f"Files with PII patterns:\n{pii_in_temp[:800]}"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Avoid writing PII to temporary files. If temporary storage "
                    "is required, use in-memory buffers (io.BytesIO) or encrypt "
                    "temp files and delete them immediately after use. Set "
                    "restrictive permissions (0600) on any temp files. Add a "
                    "Dockerfile RUN step to clean /tmp and /var/cache before "
                    "the final image layer. Mount tmpfs for /tmp in production "
                    "to ensure data does not persist across container restarts."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                    "https://docs.docker.com/storage/tmpfs/",
                ],
                cvss_score=5.0,
                ai_risk_score=6.5,
            )

        # Store anonymization check metadata
        self.context.metadata.setdefault("compliance_checks", {})["anonymization"] = {
            "has_anonymization_impl": bool(anon_refs),
            "quasi_identifiers_found": bool(quasi_refs),
            "quasi_identifier_files": qi_files[:5],
            "has_k_anonymity": bool(kanon_refs),
            "pii_in_logs": bool(pii_in_logs),
            "log_dirs_checked": log_dirs_found,
            "pii_in_temp": bool(pii_in_temp),
            "temp_dirs_checked": temp_dirs_found,
        }

    # ------------------------------------------------------------------
    # GDPR checks
    # ------------------------------------------------------------------

    async def _check_gdpr(
        self,
        has_pii: bool,
        has_secrets: bool,
        has_log_issues: bool,
        env: dict[str, str],
    ) -> None:
        """GDPR compliance checks."""
        checks: list[ComplianceCheckItem] = []

        # Art. 5 -- Data minimization
        status = CheckStatus.FAIL if has_pii else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="GDPR-5",
            article="Art. 5(1)(c)",
            requirement="Data minimization -- only process data that is necessary",
            status=status.value,
            evidence="PII detected in container files" if has_pii else "No PII detected",
        ))

        # Art. 13/14 -- Privacy notice / transparency
        privacy_files = await self._grep_container("privacy.policy\\|privacy.notice\\|data.protection")
        status = CheckStatus.PASS if privacy_files else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="GDPR-13",
            article="Art. 13-14",
            requirement="Transparency -- privacy notice available to data subjects",
            status=status.value,
            evidence=privacy_files[:500] if privacy_files else "No privacy notice files found",
        ))

        # Art. 17 -- Right to erasure
        deletion_support = await self._grep_container("delete.data\\|erasure\\|forget\\|right.to.delete")
        status = CheckStatus.PASS if deletion_support else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="GDPR-17",
            article="Art. 17",
            requirement="Right to erasure -- mechanism to delete personal data",
            status=status.value,
            evidence=deletion_support[:500] if deletion_support else "No erasure mechanism found",
        ))

        # Art. 25 -- Data protection by design (encryption)
        encryption_refs = await self._grep_container("encrypt\\|AES\\|fernet\\|cryptography")
        status = CheckStatus.PASS if encryption_refs else (CheckStatus.FAIL if has_pii else CheckStatus.PARTIAL)
        checks.append(ComplianceCheckItem(
            id="GDPR-25",
            article="Art. 25",
            requirement="Data protection by design and by default",
            status=status.value,
            evidence=encryption_refs[:500] if encryption_refs else "No encryption references found",
        ))

        # Art. 32 -- Security of processing
        status = CheckStatus.FAIL if has_secrets else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="GDPR-32",
            article="Art. 32",
            requirement="Security of processing -- appropriate technical measures",
            status=status.value,
            evidence="Plaintext secrets found" if has_secrets else "No plaintext secrets detected",
        ))

        # Art. 30 -- Records of processing
        logging_config = await self._grep_container("audit.log\\|processing.record\\|data.register")
        status = CheckStatus.PASS if logging_config else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="GDPR-30",
            article="Art. 30",
            requirement="Records of processing activities",
            status=status.value,
            evidence=logging_config[:500] if logging_config else "No processing records found",
        ))

        failed = [c for c in checks if c.status == CheckStatus.FAIL.value]
        if failed:
            details = "\n".join(
                f"  [{c.id}] {c.article}: {c.requirement} -- FAIL"
                for c in failed
            )
            self.add_finding(
                title=f"GDPR compliance gaps ({len(failed)} failed checks)",
                description=(
                    f"The AI agent container fails {len(failed)} of {len(checks)} "
                    "GDPR compliance checks. These gaps may result in regulatory "
                    "penalties and data protection violations."
                ),
                severity=Severity.HIGH if len(failed) >= 3 else Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"GDPR: {len(failed)}/{len(checks)} checks failed",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Address each failing GDPR article requirement. Implement data "
                    "minimization, provide erasure mechanisms, encrypt data at rest, "
                    "secure secrets management, and maintain processing records."
                ),
                references=[
                    "https://gdpr.eu/",
                    "https://edpb.europa.eu/",
                ],
                cvss_score=5.0,
                ai_risk_score=7.0,
            )

        # Store compliance metadata for the report
        self.context.metadata.setdefault("compliance_checks", {})["gdpr"] = [
            {"id": c.id, "article": c.article, "requirement": c.requirement,
             "status": c.status, "evidence": c.evidence}
            for c in checks
        ]

    # ------------------------------------------------------------------
    # CCPA checks
    # ------------------------------------------------------------------

    async def _check_ccpa(
        self,
        has_pii: bool,
        has_secrets: bool,
        has_log_issues: bool,
        env: dict[str, str],
    ) -> None:
        """CCPA compliance checks."""
        checks: list[ComplianceCheckItem] = []

        # Sec. 1798.100 -- Right to know
        disclosure_refs = await self._grep_container(
            "data.disclosure\\|right.to.know\\|personal.information.collected"
        )
        status = CheckStatus.PASS if disclosure_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="CCPA-100",
            article="Sec. 1798.100",
            requirement="Right to know what personal information is collected",
            status=status.value,
            evidence=disclosure_refs[:500] if disclosure_refs else "No disclosure mechanism found",
        ))

        # Sec. 1798.105 -- Right to delete
        deletion_refs = await self._grep_container("delete\\|remove.data\\|purge")
        status = CheckStatus.PASS if deletion_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="CCPA-105",
            article="Sec. 1798.105",
            requirement="Right to delete personal information",
            status=status.value,
            evidence=deletion_refs[:500] if deletion_refs else "No deletion mechanism found",
        ))

        # Sec. 1798.110 -- Right to access
        access_refs = await self._grep_container("data.access\\|export.data\\|download.data")
        status = CheckStatus.PASS if access_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="CCPA-110",
            article="Sec. 1798.110",
            requirement="Right to access personal information",
            status=status.value,
            evidence=access_refs[:500] if access_refs else "No data access mechanism found",
        ))

        # Sec. 1798.150 -- Data security
        status = CheckStatus.FAIL if has_secrets else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="CCPA-150",
            article="Sec. 1798.150",
            requirement="Reasonable security procedures for personal information",
            status=status.value,
            evidence="Plaintext secrets detected" if has_secrets else "No plaintext secrets",
        ))

        # Sec. 1798.120 -- Right to opt-out of sale
        opt_out_refs = await self._grep_container("opt.out\\|do.not.sell\\|consent")
        status = CheckStatus.PASS if opt_out_refs else CheckStatus.NOT_APPLICABLE
        checks.append(ComplianceCheckItem(
            id="CCPA-120",
            article="Sec. 1798.120",
            requirement="Right to opt-out of sale of personal information",
            status=status.value,
            evidence=opt_out_refs[:500] if opt_out_refs else "No opt-out mechanism (may not be applicable)",
        ))

        failed = [c for c in checks if c.status == CheckStatus.FAIL.value]
        if failed:
            details = "\n".join(
                f"  [{c.id}] {c.article}: {c.requirement} -- FAIL"
                for c in failed
            )
            self.add_finding(
                title=f"CCPA compliance gaps ({len(failed)} failed checks)",
                description=(
                    f"The AI agent container fails {len(failed)} of {len(checks)} "
                    "CCPA compliance checks. California consumers have a private "
                    "right of action for data breaches resulting from failures to "
                    "implement reasonable security."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"CCPA: {len(failed)}/{len(checks)} checks failed",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement consumer data rights mechanisms (access, deletion, "
                    "opt-out). Ensure reasonable security measures are in place for "
                    "all personal information processed by the AI agent."
                ),
                references=[
                    "https://oag.ca.gov/privacy/ccpa",
                ],
                cvss_score=4.5,
                ai_risk_score=6.0,
            )

        self.context.metadata.setdefault("compliance_checks", {})["ccpa"] = [
            {"id": c.id, "article": c.article, "requirement": c.requirement,
             "status": c.status, "evidence": c.evidence}
            for c in checks
        ]

    # ------------------------------------------------------------------
    # Habeas Data checks (Argentine Law 25.326)
    # ------------------------------------------------------------------

    async def _check_habeas_data(
        self,
        has_pii: bool,
        has_secrets: bool,
        has_log_issues: bool,
        env: dict[str, str],
    ) -> None:
        """Argentine Habeas Data (Ley 25.326) compliance checks."""
        checks: list[ComplianceCheckItem] = []

        # Art. 4 -- Data quality (accuracy, relevance, not excessive)
        status = CheckStatus.FAIL if has_pii else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="HD-4",
            article="Art. 4",
            requirement="Calidad de los datos -- datos adecuados, pertinentes y no excesivos",
            status=status.value,
            evidence=(
                "PII found in container may indicate excessive data collection"
                if has_pii else "No excessive PII detected"
            ),
        ))

        # Art. 5 -- Consent
        consent_refs = await self._grep_container(
            "consent\\|consentimiento\\|autorizar\\|aceptar"
        )
        status = CheckStatus.PASS if consent_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="HD-5",
            article="Art. 5",
            requirement="Consentimiento del titular -- consent from data subject",
            status=status.value,
            evidence=consent_refs[:500] if consent_refs else "No consent mechanism found",
        ))

        # Art. 9 -- Security (appropriate measures)
        status = CheckStatus.FAIL if has_secrets else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="HD-9",
            article="Art. 9",
            requirement="Seguridad de los datos -- medidas de seguridad adecuadas",
            status=status.value,
            evidence="Plaintext secrets found" if has_secrets else "No plaintext secrets",
        ))

        # Art. 10 -- Confidentiality
        status = CheckStatus.FAIL if has_log_issues else CheckStatus.PASS
        checks.append(ComplianceCheckItem(
            id="HD-10",
            article="Art. 10",
            requirement="Deber de confidencialidad -- duty of confidentiality",
            status=status.value,
            evidence=(
                "Log files may leak confidential data"
                if has_log_issues else "No confidentiality issues detected in logs"
            ),
        ))

        # Art. 14 -- Right of access
        access_refs = await self._grep_container("acceso.datos\\|data.access\\|consultar")
        status = CheckStatus.PASS if access_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="HD-14",
            article="Art. 14",
            requirement="Derecho de acceso -- right to access personal data",
            status=status.value,
            evidence=access_refs[:500] if access_refs else "No data access mechanism found",
        ))

        # Art. 16 -- Right of rectification and deletion
        rectify_refs = await self._grep_container(
            "rectif\\|supresi\\|delete\\|borrar\\|eliminar"
        )
        status = CheckStatus.PASS if rectify_refs else CheckStatus.FAIL
        checks.append(ComplianceCheckItem(
            id="HD-16",
            article="Art. 16",
            requirement="Derecho de rectificacion y supresion -- right to rectify and delete",
            status=status.value,
            evidence=rectify_refs[:500] if rectify_refs else "No rectification/deletion mechanism found",
        ))

        # Art. 12 -- International transfers
        transfer_refs = await self._grep_container(
            "transfer\\|cross.border\\|international\\|exportar"
        )
        status = CheckStatus.PASS if transfer_refs else CheckStatus.NOT_APPLICABLE
        checks.append(ComplianceCheckItem(
            id="HD-12",
            article="Art. 12",
            requirement="Cesion de datos -- controls on data transfer",
            status=status.value,
            evidence=(
                transfer_refs[:500]
                if transfer_refs else "No international transfer controls found (may not be applicable)"
            ),
        ))

        failed = [c for c in checks if c.status == CheckStatus.FAIL.value]
        if failed:
            details = "\n".join(
                f"  [{c.id}] {c.article}: {c.requirement} -- FAIL"
                for c in failed
            )
            self.add_finding(
                title=f"Habeas Data (Ley 25.326) compliance gaps ({len(failed)} failed checks)",
                description=(
                    f"The AI agent container fails {len(failed)} of {len(checks)} "
                    "compliance checks under Argentina's Personal Data Protection "
                    "Law (Ley 25.326 / Habeas Data). Non-compliance may result in "
                    "sanctions from the AAIP (Agencia de Acceso a la Informacion "
                    "Publica)."
                ),
                severity=Severity.HIGH if len(failed) >= 3 else Severity.MEDIUM,
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"Habeas Data: {len(failed)}/{len(checks)} checks failed",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement data subject rights mechanisms (access, rectification, "
                    "deletion). Obtain proper consent for data processing. Ensure "
                    "adequate security measures per Art. 9. Register databases with "
                    "the AAIP as required by Argentine law."
                ),
                references=[
                    "https://www.argentina.gob.ar/aaip",
                    "http://servicios.infoleg.gob.ar/infolegInternet/anexos/60000-64999/64790/texact.htm",
                ],
                cvss_score=5.0,
                ai_risk_score=7.0,
            )

        self.context.metadata.setdefault("compliance_checks", {})["habeas_data"] = [
            {"id": c.id, "article": c.article, "requirement": c.requirement,
             "status": c.status, "evidence": c.evidence}
            for c in checks
        ]
