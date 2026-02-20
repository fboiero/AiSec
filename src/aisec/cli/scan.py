"""``aisec scan`` command -- run security analysis scans."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

from aisec.cli.console import console
from aisec.core.config import AiSecConfig
from aisec.core.context import ScanContext
from aisec.core.enums import Severity

scan_app = typer.Typer(help="Run security analysis scans.")

_BANNER = r"""
    _    _ ____
   / \  (_) ___|  ___  ___
  / _ \ | \___ \ / _ \/ __|
 / ___ \| |___) |  __/ (__
/_/   \_\_|____/ \___|\___|
"""


def _print_banner() -> None:
    """Display the AiSec ASCII banner."""
    console.print(Panel(_BANNER, style="bold cyan", subtitle="Deep AI Agent Security Analysis"))


def _build_results_table(ctx: ScanContext) -> Table:
    """Build a Rich table summarising agent results."""
    table = Table(title="Scan Results", show_lines=True)
    table.add_column("Agent", style="agent", no_wrap=True)
    table.add_column("Findings", justify="right")
    table.add_column("Critical", justify="right", style="critical")
    table.add_column("High", justify="right", style="error")
    table.add_column("Medium", justify="right", style="warning")
    table.add_column("Low", justify="right", style="info")
    table.add_column("Duration (s)", justify="right")

    for name, result in ctx.agent_results.items():
        counts = {s: 0 for s in Severity}
        for finding in result.findings:
            counts[finding.severity] += 1
        table.add_row(
            name,
            str(len(result.findings)),
            str(counts[Severity.CRITICAL]),
            str(counts[Severity.HIGH]),
            str(counts[Severity.MEDIUM]),
            str(counts[Severity.LOW]),
            f"{result.duration_seconds:.1f}",
        )

    return table


async def _run_scan(
    image: str,
    config: AiSecConfig,
    verbose: bool,
) -> ScanContext:
    """Execute the scan pipeline (placeholder implementation)."""
    ctx = ScanContext(
        target_image=image,
        target_name=config.target_name or image.split("/")[-1].split(":")[0],
        config=config,
    )

    # Placeholder -- the real orchestrator will be wired in later.
    console.print(f"[info]Scanning [bold]{image}[/bold] ...[/info]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running agents...", total=100)
        # Simulate work
        for step in range(10):
            await asyncio.sleep(0.1)
            progress.update(task, advance=10, description=f"Phase {step + 1}/10")

    console.print("[success]Scan complete.[/success]")
    return ctx


@scan_app.callback(invoke_without_command=True)
def scan(
    image: str = typer.Argument(..., help="Docker image or target to scan."),
    agents: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--agents",
        "-a",
        help="Comma-separated list of agents to run (default: all).",
    ),
    skip_agents: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--skip-agents",
        help="Comma-separated list of agents to skip.",
    ),
    config: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--config",
        "-c",
        help="Path to aisec.yaml configuration file.",
    ),
    fmt: str = typer.Option(
        "json,html",
        "--format",
        "-f",
        help="Comma-separated output formats (json, html, pdf).",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Report language (en, es, pt).",
    ),
    compliance: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--compliance",
        help="Comma-separated compliance frameworks to evaluate.",
    ),
    timeout: int = typer.Option(
        3600,
        "--timeout",
        "-t",
        help="Maximum scan duration in seconds.",
    ),
    output_dir: str = typer.Option(
        "./aisec-reports",
        "--output-dir",
        "-o",
        help="Directory to write reports to.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output.",
    ),
) -> None:
    """Run a full security analysis scan against a target image."""
    _print_banner()

    # ── Build configuration ──────────────────────────────────────────
    overrides: dict[str, object] = {
        "target_image": image,
        "scan_timeout": timeout,
        "report_formats": [f.strip() for f in fmt.split(",")],
        "report_language": lang,
        "report_output_dir": output_dir,
    }
    if agents is not None:
        overrides["agents"] = [a.strip() for a in agents.split(",")]
    if skip_agents is not None:
        overrides["skip_agents"] = [a.strip() for a in skip_agents.split(",")]
    if compliance is not None:
        overrides["compliance_frameworks"] = [c.strip() for c in compliance.split(",")]

    if config is not None:
        cfg = AiSecConfig.from_yaml(config, **overrides)
    else:
        cfg = AiSecConfig(**overrides)  # type: ignore[arg-type]

    if verbose:
        console.print(Panel(str(cfg), title="Resolved configuration", style="dim"))

    # ── Execute scan ────────────────────────────────────────────────
    ctx = asyncio.run(_run_scan(image, cfg, verbose))

    # ── Display results ─────────────────────────────────────────────
    if ctx.agent_results:
        console.print(_build_results_table(ctx))
    else:
        console.print(
            Panel(
                "[info]No agent results yet -- orchestrator not wired.[/info]",
                title="Results",
            )
        )

    console.print(
        f"\n[success]Reports will be written to:[/success] {output_dir}\n"
    )
