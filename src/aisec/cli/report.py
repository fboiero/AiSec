"""``aisec report`` command group -- report management."""

from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel

from aisec.cli.console import console

report_app = typer.Typer(help="Report management.")


@report_app.command()
def convert(
    json_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    fmt: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Target format (html, pdf, csv, md, sarif).",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Report language (en, es, pt).",
    ),
    output: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--output",
        "-o",
        help="Output file path. Defaults to <json_file>.<format>.",
    ),
) -> None:
    """Convert a JSON scan report to another format."""
    if not json_file.exists():
        console.print(f"[error]File not found:[/error] {json_file}")
        raise typer.Exit(code=1)

    target = output or json_file.with_suffix(f".{fmt}")
    console.print(
        Panel(
            f"Converting [bold]{json_file}[/bold] -> [bold]{target}[/bold] (format={fmt}, lang={lang})",
            title="Report Conversion",
            style="info",
        )
    )

    # Load JSON report
    try:
        raw = json.loads(json_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[error]Failed to read JSON report:[/error] {exc}")
        raise typer.Exit(code=1)

    # Reconstruct ScanReport from JSON
    from aisec.core.models import ScanReport
    from aisec.reports.builder import ReportBuilder

    try:
        report = ReportBuilder.from_dict(raw)
    except Exception:
        # Fallback: create a minimal report from the raw dict
        report = _build_report_from_raw(raw)

    # Dispatch to renderer
    fmt = fmt.strip().lower()
    try:
        if fmt == "html":
            from aisec.reports.renderers import html_renderer
            result_path = html_renderer.render(report, target)
        elif fmt == "pdf":
            from aisec.reports.renderers import pdf_renderer
            result_path = pdf_renderer.render(report, target)
        elif fmt == "csv":
            from aisec.reports.renderers import csv_renderer
            result_path = csv_renderer.render(report, target)
        elif fmt in ("md", "markdown"):
            from aisec.reports.renderers import md_renderer
            result_path = md_renderer.render(report, target)
        elif fmt == "sarif":
            from aisec.reports.renderers import sarif_renderer
            result_path = sarif_renderer.render(report, target)
        elif fmt == "json":
            from aisec.reports.renderers import json_renderer
            result_path = json_renderer.render(report, target)
        else:
            console.print(f"[error]Unsupported format:[/error] {fmt}")
            console.print("[info]Supported: html, pdf, csv, md, sarif, json[/info]")
            raise typer.Exit(code=1)
    except ImportError as exc:
        console.print(f"[error]Missing dependency for {fmt} format:[/error] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[error]Conversion failed:[/error] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[success]Report written to:[/success] {result_path}")


def _build_report_from_raw(raw: dict) -> object:
    """Build a minimal ScanReport from a raw JSON dict."""
    from aisec.core.models import (
        ScanReport, ExecutiveSummary, RiskOverview, Finding,
        AgentResult, ComplianceReport, CorrelatedRisk,
    )
    from aisec.core.enums import Severity, FindingStatus
    from uuid import UUID
    from datetime import datetime

    def _parse_severity(val: str) -> Severity:
        try:
            return Severity(val)
        except (ValueError, KeyError):
            return Severity.INFO

    def _parse_finding(d: dict) -> Finding:
        return Finding(
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=_parse_severity(d.get("severity", "info")),
            agent=d.get("agent", ""),
            remediation=d.get("remediation", ""),
            cvss_score=d.get("cvss_score"),
            ai_risk_score=d.get("ai_risk_score"),
            owasp_llm=d.get("owasp_llm", []),
            owasp_agentic=d.get("owasp_agentic", []),
            nist_ai_rmf=d.get("nist_ai_rmf", []),
        )

    es_data = raw.get("executive_summary", {})
    es = ExecutiveSummary(
        overall_risk_level=_parse_severity(es_data.get("overall_risk_level", "info")),
        total_findings=es_data.get("total_findings", 0),
        critical_count=es_data.get("critical_count", 0),
        high_count=es_data.get("high_count", 0),
        medium_count=es_data.get("medium_count", 0),
        low_count=es_data.get("low_count", 0),
        info_count=es_data.get("info_count", 0),
        top_risks=es_data.get("top_risks", []),
        summary_text=es_data.get("summary_text", ""),
    )

    ro_data = raw.get("risk_overview", {})
    ro = RiskOverview(
        ai_risk_score=ro_data.get("ai_risk_score", 0.0),
        attack_surface_score=ro_data.get("attack_surface_score", 0.0),
        data_exposure_score=ro_data.get("data_exposure_score", 0.0),
        agency_risk_score=ro_data.get("agency_risk_score", 0.0),
        supply_chain_score=ro_data.get("supply_chain_score", 0.0),
        compliance_score=ro_data.get("compliance_score", 0.0),
    )

    all_findings = [_parse_finding(f) for f in raw.get("all_findings", [])]

    return ScanReport(
        target_name=raw.get("target_name", ""),
        target_image=raw.get("target_image", ""),
        aisec_version=raw.get("aisec_version", ""),
        language=raw.get("language", "en"),
        executive_summary=es,
        risk_overview=ro,
        all_findings=all_findings,
    )


@report_app.command()
def view(
    report_file: Path = typer.Argument(..., help="Path to a report file to open."),
) -> None:
    """Open a report file in the default viewer."""
    if not report_file.exists():
        console.print(f"[error]File not found:[/error] {report_file}")
        raise typer.Exit(code=1)

    console.print(f"[info]Opening [bold]{report_file}[/bold] ...[/info]")

    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["open", str(report_file)], check=True)  # noqa: S603, S607
        elif system == "Linux":
            subprocess.run(["xdg-open", str(report_file)], check=True)  # noqa: S603, S607
        elif system == "Windows":
            subprocess.run(["start", "", str(report_file)], check=True, shell=True)  # noqa: S603, S607, S602
        else:
            console.print(f"[warning]Unsupported platform: {system}[/warning]")
    except subprocess.CalledProcessError:
        console.print("[error]Failed to open the report file.[/error]")
        raise typer.Exit(code=1)
