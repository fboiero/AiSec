"""Markdown report renderer.

Produces a structured Markdown document from a
:class:`~aisec.core.models.ScanReport`, suitable for GitHub
READMEs, pull request comments, and documentation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from uuid import UUID

from aisec.core.models import ScanReport


def _sev_value(sev: object) -> str:
    """Extract severity string value."""
    if isinstance(sev, Enum):
        return sev.value
    return str(sev)


def render(report: ScanReport, output_path: Path) -> Path:
    """Render a scan report to a Markdown file.

    Args:
        report: The complete scan report.
        output_path: Destination file path.

    Returns:
        The resolved path to the written Markdown file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    es = report.executive_summary
    ro = report.risk_overview

    # Title
    lines.append(f"# AiSec Security Report: {report.target_name}")
    lines.append("")

    # Metadata
    scan_date = ""
    if report.generated_at:
        scan_date = (
            report.generated_at.isoformat()
            if isinstance(report.generated_at, datetime)
            else str(report.generated_at)
        )
    lines.append(f"- **Target:** {report.target_image}")
    lines.append(f"- **Date:** {scan_date}")
    lines.append(f"- **AiSec Version:** {report.aisec_version}")
    lines.append(f"- **Duration:** {report.scan_duration_seconds:.1f}s")
    lines.append(f"- **Language:** {report.language}")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    risk_level = _sev_value(es.overall_risk_level)
    lines.append(f"**Overall Risk Level:** {risk_level}")
    lines.append(f"**Total Findings:** {es.total_findings}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| Critical | {es.critical_count} |")
    lines.append(f"| High | {es.high_count} |")
    lines.append(f"| Medium | {es.medium_count} |")
    lines.append(f"| Low | {es.low_count} |")
    lines.append(f"| Info | {es.info_count} |")
    lines.append("")

    if es.summary_text:
        lines.append(es.summary_text)
        lines.append("")

    if es.top_risks:
        lines.append("### Top Risks")
        lines.append("")
        for risk in es.top_risks:
            lines.append(f"- {risk}")
        lines.append("")

    # Risk Overview
    lines.append("## Risk Overview")
    lines.append("")
    lines.append(f"- **AI Risk Score:** {ro.ai_risk_score:.1f}")
    lines.append(f"- **Attack Surface:** {ro.attack_surface_score:.1f}")
    lines.append(f"- **Data Exposure:** {ro.data_exposure_score:.1f}")
    lines.append(f"- **Agency Risk:** {ro.agency_risk_score:.1f}")
    lines.append(f"- **Supply Chain:** {ro.supply_chain_score:.1f}")
    lines.append(f"- **Compliance Score:** {ro.compliance_score:.0f}%")
    lines.append("")

    # Findings by Agent
    if report.agent_results:
        lines.append("## Findings by Agent")
        lines.append("")
        for agent_name, result in sorted(report.agent_results.items()):
            findings = result.findings
            if not findings:
                continue
            lines.append(f"### {agent_name} ({len(findings)} findings)")
            lines.append("")
            lines.append("| Severity | Title | Status |")
            lines.append("|----------|-------|--------|")
            for f in findings:
                sev = _sev_value(f.severity)
                status = _sev_value(f.status) if hasattr(f.status, "value") else str(f.status)
                title = f.title.replace("|", "\\|")
                lines.append(f"| {sev} | {title} | {status} |")
            lines.append("")

    # All Findings detail
    if report.all_findings:
        lines.append("## All Findings")
        lines.append("")
        for f in report.all_findings:
            sev = _sev_value(f.severity)
            lines.append(f"### [{sev}] {f.title}")
            lines.append("")
            if f.description:
                lines.append(f.description)
                lines.append("")
            lines.append(f"- **Agent:** {f.agent}")
            if f.cvss_score is not None:
                lines.append(f"- **CVSS:** {f.cvss_score}")
            if f.ai_risk_score is not None:
                lines.append(f"- **AI Risk Score:** {f.ai_risk_score}")
            if f.remediation:
                lines.append(f"- **Remediation:** {f.remediation}")
            lines.append("")

    # Correlated Risks
    if report.correlated_risks:
        lines.append("## Correlated Risks")
        lines.append("")
        for cr in report.correlated_risks:
            sev = _sev_value(cr.severity)
            lines.append(f"### [{sev}] {cr.name}")
            lines.append("")
            if cr.description:
                lines.append(cr.description)
                lines.append("")
            agents = ", ".join(cr.agents_involved)
            lines.append(f"- **Agents Involved:** {agents}")
            if cr.remediation:
                lines.append(f"- **Remediation:** {cr.remediation}")
            lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by AiSec {report.aisec_version}*")
    lines.append("")

    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return output_path.resolve()
