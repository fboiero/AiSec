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
        all_checklists = [
            compliance.gdpr, compliance.ccpa, compliance.habeas_data,
            compliance.eu_ai_act, compliance.iso_42001,
            compliance.nist_ai_600_1, compliance.argentina_ai,
        ]
        total_checks = sum(cl.total_checks for cl in all_checklists)
        total_passed = sum(cl.passed for cl in all_checklists)
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
        """Evaluate compliance checklists for all supported frameworks.

        This is a heuristic evaluation based on finding categories. A full
        compliance audit would require additional context and manual review.
        """
        from aisec.frameworks.compliance.gdpr import evaluate_gdpr
        from aisec.frameworks.compliance.ccpa import evaluate_ccpa
        from aisec.frameworks.compliance.habeas_data import evaluate_habeas_data

        # Use the dedicated compliance evaluators
        gdpr = evaluate_gdpr(findings, [])
        ccpa = evaluate_ccpa(findings, [])
        habeas_data = evaluate_habeas_data(findings, [])

        # New Q4 frameworks -- imported lazily to avoid circular imports
        try:
            from aisec.frameworks.compliance.eu_ai_act import evaluate_eu_ai_act
            eu_ai_act = evaluate_eu_ai_act(findings, [])
        except ImportError:
            eu_ai_act = ComplianceChecklist(framework_name="EU AI Act")

        try:
            from aisec.frameworks.compliance.iso_42001 import evaluate_iso_42001
            iso_42001 = evaluate_iso_42001(findings, [])
        except ImportError:
            iso_42001 = ComplianceChecklist(framework_name="ISO/IEC 42001:2023")

        try:
            from aisec.frameworks.nist_ai_600_1 import evaluate_nist_600_1
            nist_ai_600_1 = evaluate_nist_600_1(findings, [])
        except ImportError:
            nist_ai_600_1 = ComplianceChecklist(framework_name="NIST AI 600-1")

        try:
            from aisec.frameworks.compliance.argentina_ai import evaluate_argentina_ai
            argentina_ai = evaluate_argentina_ai(findings, [])
        except ImportError:
            argentina_ai = ComplianceChecklist(framework_name="Argentina AI Governance")

        return ComplianceReport(
            gdpr=gdpr,
            ccpa=ccpa,
            habeas_data=habeas_data,
            eu_ai_act=eu_ai_act,
            iso_42001=iso_42001,
            nist_ai_600_1=nist_ai_600_1,
            argentina_ai=argentina_ai,
        )
