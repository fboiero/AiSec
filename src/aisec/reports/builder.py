"""Report assembly engine.

Collects findings from all agents, deduplicates, maps to frameworks,
computes risk scores, evaluates compliance, and produces a complete
:class:`~aisec.core.models.ScanReport`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aisec.core.enums import ComplianceFramework, Severity
from aisec.core.models import (
    AgentResult,
    ComplianceChecklist,
    ComplianceCheckItem,
    ComplianceReport,
    ExecutiveSummary,
    Finding,
    ScanReport,
)
from aisec.reports.scoring import compute_risk_overview, score_finding
from aisec.frameworks.owasp_llm import map_findings as map_owasp_llm

if TYPE_CHECKING:
    from aisec.core.context import ScanContext

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Assembles a :class:`ScanReport` from scan context and agent results."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, context: ScanContext, language: str = "en") -> ScanReport:
        """Build a complete scan report from the scan context.

        Args:
            context: The shared scan context containing all agent results.
            language: ISO-639-1 language code (``"en"`` or ``"es"``).

        Returns:
            A fully populated :class:`ScanReport`.
        """
        # 1. Collect all findings from every agent result
        all_findings = self._collect_findings(context.agent_results)

        # 2. Deduplicate findings by title
        unique_findings = self._deduplicate(all_findings)

        # 3. Map findings to OWASP LLM categories
        owasp_llm_map = map_owasp_llm(unique_findings)

        # 4. Map findings to OWASP Agentic categories
        owasp_agentic_map = self._map_owasp_agentic(unique_findings)

        # 5. Map findings to NIST AI RMF functions
        nist_ai_rmf_map = self._map_nist_ai_rmf(unique_findings)

        # 6. Compute executive summary
        executive_summary = self._compute_executive_summary(unique_findings)

        # 7. Compute risk overview
        risk_overview = compute_risk_overview(unique_findings)

        # 8. Evaluate compliance
        compliance = self._evaluate_compliance(unique_findings)

        # Update risk_overview compliance score from checklist results
        total_checks = (
            compliance.gdpr.total_checks
            + compliance.ccpa.total_checks
            + compliance.habeas_data.total_checks
        )
        total_passed = (
            compliance.gdpr.passed
            + compliance.ccpa.passed
            + compliance.habeas_data.passed
        )
        if total_checks > 0:
            risk_overview.compliance_score = round(
                (total_passed / total_checks) * 100.0, 1
            )

        # Compute scan duration
        elapsed = (
            datetime.now(timezone.utc) - context.started_at
        ).total_seconds()

        # Assign AI risk scores to individual findings
        for finding in unique_findings:
            if finding.ai_risk_score is None:
                finding.ai_risk_score = score_finding(finding)

        # Resolve version
        try:
            from aisec import __version__
        except ImportError:
            __version__ = "unknown"

        return ScanReport(
            scan_id=context.scan_id,
            target_name=context.target_name,
            target_image=context.target_image,
            aisec_version=__version__,
            scan_duration_seconds=round(elapsed, 2),
            language=language,
            executive_summary=executive_summary,
            risk_overview=risk_overview,
            owasp_llm_findings=owasp_llm_map,
            owasp_agentic_findings=owasp_agentic_map,
            nist_ai_rmf_findings=nist_ai_rmf_map,
            agent_results=dict(context.agent_results),
            compliance=compliance,
            all_findings=unique_findings,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_findings(
        agent_results: dict[str, AgentResult],
    ) -> list[Finding]:
        """Flatten findings from all agent results into a single list."""
        findings: list[Finding] = []
        for result in agent_results.values():
            findings.extend(result.findings)
        return findings

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on title (keep first occurrence)."""
        seen_titles: set[str] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = finding.title.strip().lower()
            if key and key not in seen_titles:
                seen_titles.add(key)
                unique.append(finding)
            elif not key:
                # Keep findings with empty titles (edge case)
                unique.append(finding)
        return unique

    @staticmethod
    def _map_owasp_agentic(
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """Group findings by their OWASP Agentic Top 10 category."""
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            for category_id in finding.owasp_agentic:
                normalised = category_id.strip().upper()
                grouped.setdefault(normalised, []).append(finding)
        return grouped

    @staticmethod
    def _map_nist_ai_rmf(
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """Group findings by their NIST AI RMF function."""
        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            for function_id in finding.nist_ai_rmf:
                normalised = function_id.strip().upper()
                grouped.setdefault(normalised, []).append(finding)
        return grouped

    @staticmethod
    def _compute_executive_summary(
        findings: list[Finding],
    ) -> ExecutiveSummary:
        """Compute counts, top risks, and overall risk level."""
        counts = {s: 0 for s in Severity}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        # Determine overall risk level
        if counts[Severity.CRITICAL] > 0:
            overall = Severity.CRITICAL
        elif counts[Severity.HIGH] > 0:
            overall = Severity.HIGH
        elif counts[Severity.MEDIUM] > 0:
            overall = Severity.MEDIUM
        elif counts[Severity.LOW] > 0:
            overall = Severity.LOW
        else:
            overall = Severity.INFO

        # Top risks: titles of the highest severity findings (up to 5)
        priority_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        top_risks: list[str] = []
        for severity in priority_order:
            for finding in findings:
                if finding.severity == severity and finding.title:
                    top_risks.append(finding.title)
                    if len(top_risks) >= 5:
                        break
            if len(top_risks) >= 5:
                break

        # Summary text
        total = len(findings)
        if total == 0:
            summary_text = "No security findings were identified during the scan."
        else:
            summary_text = (
                f"The scan identified {total} finding(s): "
                f"{counts[Severity.CRITICAL]} critical, "
                f"{counts[Severity.HIGH]} high, "
                f"{counts[Severity.MEDIUM]} medium, "
                f"{counts[Severity.LOW]} low, "
                f"{counts[Severity.INFO]} informational."
            )

        return ExecutiveSummary(
            overall_risk_level=overall,
            total_findings=total,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            top_risks=top_risks,
            summary_text=summary_text,
        )

    @staticmethod
    def _evaluate_compliance(
        findings: list[Finding],
    ) -> ComplianceReport:
        """Evaluate compliance checklists for GDPR, CCPA, and Habeas Data.

        This is a heuristic evaluation based on finding categories. A full
        compliance audit would require additional context and manual review.
        """

        def _has_category(target_ids: set[str]) -> bool:
            """Check whether any finding maps to the given category IDs."""
            for f in findings:
                if target_ids & (set(f.owasp_llm) | set(f.owasp_agentic)):
                    return True
            return False

        # -- GDPR ----------------------------------------------------------
        gdpr_items = [
            ComplianceCheckItem(
                id="GDPR-1",
                article="Art. 5(1)(f)",
                requirement="Integrity and confidentiality of personal data",
                status="fail" if _has_category({"LLM02", "LLM07"}) else "pass",
                evidence="Sensitive data disclosure or system prompt leakage detected"
                if _has_category({"LLM02", "LLM07"})
                else "No data disclosure findings",
            ),
            ComplianceCheckItem(
                id="GDPR-2",
                article="Art. 25",
                requirement="Data protection by design and by default",
                status="fail" if _has_category({"LLM02", "ASI06"}) else "pass",
                evidence="Data exposure or context poisoning findings present"
                if _has_category({"LLM02", "ASI06"})
                else "No data protection design issues found",
            ),
            ComplianceCheckItem(
                id="GDPR-3",
                article="Art. 32",
                requirement="Security of processing",
                status="fail"
                if _has_category({"LLM01", "LLM05", "ASI01", "ASI05"})
                else "pass",
                evidence="Injection or code execution vulnerabilities detected"
                if _has_category({"LLM01", "LLM05", "ASI01", "ASI05"})
                else "No processing security issues found",
            ),
            ComplianceCheckItem(
                id="GDPR-4",
                article="Art. 35",
                requirement="Data protection impact assessment",
                status="partial",
                evidence="Automated DPIA assessment not yet supported; manual review recommended",
            ),
        ]
        gdpr = ComplianceChecklist(
            framework_name="GDPR",
            total_checks=len(gdpr_items),
            passed=sum(1 for i in gdpr_items if i.status == "pass"),
            failed=sum(1 for i in gdpr_items if i.status == "fail"),
            not_applicable=sum(1 for i in gdpr_items if i.status == "n/a"),
            items=gdpr_items,
        )

        # -- CCPA -----------------------------------------------------------
        ccpa_items = [
            ComplianceCheckItem(
                id="CCPA-1",
                article="Sec. 1798.100",
                requirement="Right to know about personal information collected",
                status="fail" if _has_category({"LLM02"}) else "pass",
                evidence="Sensitive information disclosure findings present"
                if _has_category({"LLM02"})
                else "No personal information disclosure issues",
            ),
            ComplianceCheckItem(
                id="CCPA-2",
                article="Sec. 1798.150",
                requirement="Data breach provisions",
                status="fail" if _has_category({"LLM02", "LLM07", "ASI06"}) else "pass",
                evidence="Potential data breach vectors identified"
                if _has_category({"LLM02", "LLM07", "ASI06"})
                else "No data breach vectors identified",
            ),
            ComplianceCheckItem(
                id="CCPA-3",
                article="Sec. 1798.185",
                requirement="Reasonable security measures",
                status="fail"
                if _has_category({"LLM01", "LLM06", "ASI01", "ASI02"})
                else "pass",
                evidence="Security control weaknesses detected"
                if _has_category({"LLM01", "LLM06", "ASI01", "ASI02"})
                else "Reasonable security measures appear in place",
            ),
        ]
        ccpa = ComplianceChecklist(
            framework_name="CCPA",
            total_checks=len(ccpa_items),
            passed=sum(1 for i in ccpa_items if i.status == "pass"),
            failed=sum(1 for i in ccpa_items if i.status == "fail"),
            not_applicable=sum(1 for i in ccpa_items if i.status == "n/a"),
            items=ccpa_items,
        )

        # -- Habeas Data (Argentina Ley 25.326) ----------------------------
        habeas_items = [
            ComplianceCheckItem(
                id="HD-1",
                article="Art. 9",
                requirement="Seguridad de los datos - medidas tecnicas y organizativas",
                status="fail"
                if _has_category({"LLM01", "LLM05", "ASI01", "ASI05"})
                else "pass",
                evidence="Vulnerabilidades de inyeccion o ejecucion de codigo detectadas"
                if _has_category({"LLM01", "LLM05", "ASI01", "ASI05"})
                else "No se encontraron problemas de seguridad de procesamiento",
            ),
            ComplianceCheckItem(
                id="HD-2",
                article="Art. 10",
                requirement="Deber de confidencialidad",
                status="fail" if _has_category({"LLM02", "LLM07"}) else "pass",
                evidence="Divulgacion de informacion sensible o fuga de prompt del sistema"
                if _has_category({"LLM02", "LLM07"})
                else "No se detectaron problemas de confidencialidad",
            ),
            ComplianceCheckItem(
                id="HD-3",
                article="Art. 25",
                requirement="Control y acceso a datos personales",
                status="fail" if _has_category({"LLM06", "ASI02", "ASI03"}) else "pass",
                evidence="Riesgos de agencia excesiva o abuso de privilegios detectados"
                if _has_category({"LLM06", "ASI02", "ASI03"})
                else "Controles de acceso adecuados",
            ),
        ]
        habeas_data = ComplianceChecklist(
            framework_name="Habeas Data (Ley 25.326)",
            total_checks=len(habeas_items),
            passed=sum(1 for i in habeas_items if i.status == "pass"),
            failed=sum(1 for i in habeas_items if i.status == "fail"),
            not_applicable=sum(1 for i in habeas_items if i.status == "n/a"),
            items=habeas_items,
        )

        return ComplianceReport(
            gdpr=gdpr,
            ccpa=ccpa,
            habeas_data=habeas_data,
        )
