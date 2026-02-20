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
