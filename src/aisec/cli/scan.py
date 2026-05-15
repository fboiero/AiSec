"""``aisec scan`` command -- run security analysis scans."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
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
from aisec.core.metrics import (
    record_scan_start,
    record_scan_complete,
    record_finding,
    record_agent_duration,
)

logger = logging.getLogger(__name__)

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
    """Execute the full scan pipeline.

    1. Create scan context
    2. Set up Docker sandbox (if Docker available)
    3. Register core agents + plugins
    4. Run orchestrator
    5. Build report
    6. Render to selected formats
    7. Clean up sandbox
    """
    from aisec.agents.orchestrator import OrchestratorAgent
    from aisec.agents.registry import AgentRegistry, register_core_agents, default_registry
    from aisec.docker_.manager import DockerManager
    from aisec.plugins.loader import discover_plugins
    from aisec.reports.builder import ReportBuilder
    from aisec.reports.renderers import json_renderer, html_renderer, pdf_renderer, sarif_renderer
    from aisec.reports.renderers import csv_renderer, md_renderer

    ctx = ScanContext(
        target_image=image,
        target_name=config.target_name or image.split("/")[-1].split(":")[0],
        config=config,
    )

    # ── Phase 1: Docker sandbox ──────────────────────────────────────
    docker_available = False
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        setup_task = progress.add_task("Setting up Docker sandbox...", total=3)

        try:
            dm = DockerManager(
                target_image=image,
                scan_id=str(ctx.scan_id),
                memory_limit=config.container_memory_limit,
                cpu_limit=config.container_cpu_limit,
            )
            progress.update(setup_task, advance=1, description="Pulling image and starting container...")
            sandbox = await dm.setup_sandbox()
            ctx.docker_manager = dm
            ctx.container_id = sandbox.target.id if sandbox.target else None
            docker_available = True
            progress.update(setup_task, advance=2, description="Docker sandbox ready")
        except Exception as exc:
            progress.update(setup_task, advance=3, description="Docker not available")
            console.print(
                f"[warning]Docker sandbox unavailable: {exc}[/warning]\n"
                "[info]Running static analysis only (no container introspection).[/info]"
            )

    # ── Phase 2: Register agents ─────────────────────────────────────
    register_core_agents()
    registry = default_registry

    # Load plugins
    plugins = discover_plugins()
    for plugin in plugins:
        try:
            plugin.register_agents(registry)
            if verbose:
                console.print(f"  [info]Plugin loaded: {plugin.name} v{plugin.version}[/info]")
        except Exception as exc:
            console.print(f"  [warning]Plugin {plugin.name} failed: {exc}[/warning]")

    agent_count = len(registry.get_enabled(config))
    console.print(f"[info]Scanning [bold]{image}[/bold] with {agent_count} agents...[/info]")

    # ── Phase 3: Run orchestrator ────────────────────────────────────
    record_scan_start()
    _scan_start = time.monotonic()
    orchestrator = OrchestratorAgent(ctx, registry)

    # Track progress via events
    completed_count = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        scan_task = progress.add_task("Running security agents...", total=agent_count)

        def _on_agent_complete(result: object) -> None:
            nonlocal completed_count
            completed_count += 1
            agent_name = getattr(result, "agent", "unknown")
            findings = getattr(result, "findings", [])
            finding_count = len(findings)
            duration = getattr(result, "duration_seconds", 0.0)
            record_agent_duration(agent_name, duration)
            for f in findings:
                record_finding(getattr(f, "severity", "unknown").value if hasattr(getattr(f, "severity", None), "value") else str(getattr(f, "severity", "unknown")))
            progress.update(
                scan_task,
                advance=1,
                description=f"Agent [bold]{agent_name}[/bold] done ({finding_count} findings)",
            )

        ctx.event_bus.on("agent.completed", _on_agent_complete)

        scan_failed = False
        try:
            await orchestrator.run_scan()
        except Exception as exc:
            scan_failed = True
            console.print(f"[error]Scan error: {exc}[/error]")
            logger.exception("Scan failed")
        finally:
            record_scan_complete(time.monotonic() - _scan_start, failed=scan_failed)

    # ── Phase 4: Build report ────────────────────────────────────────
    console.print("[info]Building report...[/info]")
    builder = ReportBuilder()
    report = builder.build(ctx, language=config.report_language)

    # ── Phase 5: Render outputs ──────────────────────────────────────
    output_dir = Path(config.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"aisec-{ctx.target_name}-{str(ctx.scan_id)[:8]}"

    rendered_files: list[Path] = []
    for fmt in config.report_formats:
        fmt = fmt.strip().lower()
        try:
            if fmt == "json":
                path = json_renderer.render(report, output_dir / f"{base_name}.json")
                rendered_files.append(path)
            elif fmt == "html":
                path = html_renderer.render(report, output_dir / f"{base_name}.html")
                rendered_files.append(path)
            elif fmt == "pdf":
                path = pdf_renderer.render(report, output_dir / f"{base_name}.pdf")
                rendered_files.append(path)
            elif fmt == "sarif":
                path = sarif_renderer.render(report, output_dir / f"{base_name}.sarif")
                rendered_files.append(path)
            elif fmt == "csv":
                path = csv_renderer.render(report, output_dir / f"{base_name}.csv")
                rendered_files.append(path)
            elif fmt in ("md", "markdown"):
                path = md_renderer.render(report, output_dir / f"{base_name}.md")
                rendered_files.append(path)
            else:
                console.print(f"[warning]Unknown format: {fmt}[/warning]")
        except Exception as exc:
            console.print(f"[warning]Failed to render {fmt}: {exc}[/warning]")
            logger.exception("Render failed for format %s", fmt)

    # ── Phase 6: Cleanup ─────────────────────────────────────────────
    if docker_available and ctx.docker_manager:
        try:
            await ctx.docker_manager.cleanup()
        except Exception:
            logger.warning("Docker cleanup failed", exc_info=True)

    # Store rendered paths in metadata for display
    ctx.metadata["rendered_files"] = [str(p) for p in rendered_files]
    ctx.metadata["report"] = report

    console.print("[success]Scan complete.[/success]")
    return ctx


async def _run_scan_with_dashboard(
    image: str,
    config: AiSecConfig,
    verbose: bool,
) -> ScanContext:
    """Execute the full scan pipeline with the interactive TUI dashboard.

    Mirrors ``_run_scan`` but replaces the basic Progress bars in Phase 3
    with the rich Live dashboard.
    """
    from aisec.agents.orchestrator import OrchestratorAgent
    from aisec.agents.registry import register_core_agents, default_registry
    from aisec.cli.dashboard import ScanDashboard
    from aisec.docker_.manager import DockerManager
    from aisec.plugins.loader import discover_plugins
    from aisec.reports.builder import ReportBuilder
    from aisec.reports.renderers import json_renderer, html_renderer, pdf_renderer, sarif_renderer
    from aisec.reports.renderers import csv_renderer, md_renderer

    ctx = ScanContext(
        target_image=image,
        target_name=config.target_name or image.split("/")[-1].split(":")[0],
        config=config,
    )

    # ── Phase 1: Docker sandbox ──────────────────────────────────────
    docker_available = False
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        setup_task = progress.add_task("Setting up Docker sandbox...", total=3)

        try:
            dm = DockerManager(
                target_image=image,
                scan_id=str(ctx.scan_id),
                memory_limit=config.container_memory_limit,
                cpu_limit=config.container_cpu_limit,
            )
            progress.update(setup_task, advance=1, description="Pulling image and starting container...")
            sandbox = await dm.setup_sandbox()
            ctx.docker_manager = dm
            ctx.container_id = sandbox.target.id if sandbox.target else None
            docker_available = True
            progress.update(setup_task, advance=2, description="Docker sandbox ready")
        except Exception as exc:
            progress.update(setup_task, advance=3, description="Docker not available")
            console.print(
                f"[warning]Docker sandbox unavailable: {exc}[/warning]\n"
                "[info]Running static analysis only (no container introspection).[/info]"
            )

    # ── Phase 2: Register agents ─────────────────────────────────────
    register_core_agents()
    registry = default_registry

    plugins = discover_plugins()
    for plugin in plugins:
        try:
            plugin.register_agents(registry)
            if verbose:
                console.print(f"  [info]Plugin loaded: {plugin.name} v{plugin.version}[/info]")
        except Exception as exc:
            console.print(f"  [warning]Plugin {plugin.name} failed: {exc}[/warning]")

    agent_count = len(registry.get_enabled(config))

    # ── Phase 3: Run orchestrator (with dashboard) ───────────────────
    record_scan_start()
    _scan_start = time.monotonic()
    orchestrator = OrchestratorAgent(ctx, registry)

    scan_failed = False
    async with ScanDashboard(ctx) as dashboard:
        dashboard.set_agent_count(agent_count)
        try:
            await orchestrator.run_scan()
        except Exception as exc:
            scan_failed = True
            console.print(f"[error]Scan error: {exc}[/error]")
            logger.exception("Scan failed")
        finally:
            record_scan_complete(time.monotonic() - _scan_start, failed=scan_failed)

    # ── Phase 4: Build report ────────────────────────────────────────
    console.print("[info]Building report...[/info]")
    builder = ReportBuilder()
    report = builder.build(ctx, language=config.report_language)

    # ── Phase 5: Render outputs ──────────────────────────────────────
    output_dir = Path(config.report_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"aisec-{ctx.target_name}-{str(ctx.scan_id)[:8]}"

    rendered_files: list[Path] = []
    for fmt in config.report_formats:
        fmt = fmt.strip().lower()
        try:
            if fmt == "json":
                path = json_renderer.render(report, output_dir / f"{base_name}.json")
                rendered_files.append(path)
            elif fmt == "html":
                path = html_renderer.render(report, output_dir / f"{base_name}.html")
                rendered_files.append(path)
            elif fmt == "pdf":
                path = pdf_renderer.render(report, output_dir / f"{base_name}.pdf")
                rendered_files.append(path)
            elif fmt == "sarif":
                path = sarif_renderer.render(report, output_dir / f"{base_name}.sarif")
                rendered_files.append(path)
            elif fmt == "csv":
                path = csv_renderer.render(report, output_dir / f"{base_name}.csv")
                rendered_files.append(path)
            elif fmt in ("md", "markdown"):
                path = md_renderer.render(report, output_dir / f"{base_name}.md")
                rendered_files.append(path)
            else:
                console.print(f"[warning]Unknown format: {fmt}[/warning]")
        except Exception as exc:
            console.print(f"[warning]Failed to render {fmt}: {exc}[/warning]")
            logger.exception("Render failed for format %s", fmt)

    # ── Phase 6: Cleanup ─────────────────────────────────────────────
    if docker_available and ctx.docker_manager:
        try:
            await ctx.docker_manager.cleanup()
        except Exception:
            logger.warning("Docker cleanup failed", exc_info=True)

    ctx.metadata["rendered_files"] = [str(p) for p in rendered_files]
    ctx.metadata["report"] = report

    console.print("[success]Scan complete.[/success]")
    return ctx


@scan_app.command(name="run")
def scan(
    image: str = typer.Argument(..., help="Docker image(s) to scan. Comma-separated for multi-target."),
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
    dashboard: bool = typer.Option(
        True,
        "--dashboard/--no-dashboard",
        help="Enable interactive TUI dashboard (default: on for interactive terminals).",
    ),
    cloud_storage: bool = typer.Option(
        False,
        "--cloud-storage/--no-cloud-storage",
        help="Upload reports to cloud storage after rendering (configure via AISEC_CLOUD_STORAGE_*).",
    ),
    profile: Optional[str] = typer.Option(  # noqa: UP007
        None,
        "--profile",
        "-P",
        help="Target profile (autogpt, crewai, langchain, llamaindex, huggingface, full, quick).",
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

    if profile is not None:
        from aisec.core.target_profiles import get_profile, apply_profile
        tp = get_profile(profile)
        if tp is None:
            console.print(f"[error]Unknown profile: {profile}[/error]")
            raise typer.Exit(code=1)
        cfg = apply_profile(cfg, tp)
        console.print(f"[info]Using profile: [bold]{tp.display_name}[/bold][/info]")

    if verbose:
        import logging as _logging
        _logging.basicConfig(level=_logging.DEBUG, format="%(name)s %(message)s")
        console.print(Panel(str(cfg), title="Resolved configuration", style="dim"))

    # ── Multi-target support ────────────────────────────────────────
    images = [img.strip() for img in image.split(",") if img.strip()]

    use_dashboard = dashboard and sys.stdout.isatty()

    for idx, target_image in enumerate(images):
        if len(images) > 1:
            console.print(
                f"\n[bold cyan]── Target {idx + 1}/{len(images)}: {target_image} ──[/bold cyan]"
            )
            # Override target image in config for each target
            target_cfg = AiSecConfig(
                **{
                    **{k: getattr(cfg, k) for k in cfg.model_fields},
                    "target_image": target_image,
                }
            )
        else:
            target_cfg = cfg

        if use_dashboard:
            ctx = asyncio.run(_run_scan_with_dashboard(target_image, target_cfg, verbose))
        else:
            ctx = asyncio.run(_run_scan(target_image, target_cfg, verbose))

        # ── Display results ─────────────────────────────────────────
        if ctx.agent_results:
            console.print(_build_results_table(ctx))

            total_findings = sum(len(r.findings) for r in ctx.agent_results.values())
            console.print(
                f"\n[info]Total findings: [bold]{total_findings}[/bold] "
                f"across {len(ctx.agent_results)} agents[/info]"
            )
        else:
            console.print(
                Panel("[warning]No agent results produced.[/warning]", title="Results")
            )

        # ── Cloud storage upload ──────────────────────────────────────
        rendered = ctx.metadata.get("rendered_files", [])
        if cloud_storage and rendered and target_cfg.cloud_storage_backend:
            try:
                from aisec.core.cloud_storage import get_storage_backend
                backend = get_storage_backend(target_cfg)
                console.print("[info]Uploading reports to cloud storage...[/info]")
                for rpath in rendered:
                    uri = backend.upload(Path(rpath))
                    console.print(f"  [success]Uploaded:[/success] {uri}")
            except Exception as exc:
                console.print(f"[warning]Cloud storage upload failed: {exc}[/warning]")

        # ── Report paths ─────────────────────────────────────────────
        if rendered:
            console.print("\n[success]Reports written to:[/success]")
            for path in rendered:
                console.print(f"  {path}")
        console.print()

    if len(images) > 1:
        console.print(f"[bold green]All {len(images)} targets scanned.[/bold green]")


@scan_app.command("list")
def scan_list(
    target: Optional[str] = typer.Option(  # noqa: UP007
        None, "--target", "-t", help="Filter by target image."
    ),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results."),
) -> None:
    """List scan history from the local database."""
    from aisec.core.history import ScanHistory

    history = ScanHistory()
    try:
        scans = history.list_scans(target_image=target, limit=limit)
        if not scans:
            console.print("[dim]No scans found.[/dim]")
            return

        table = Table(title=f"Scan History ({len(scans)} scans)")
        table.add_column("Scan ID", style="bold", no_wrap=True)
        table.add_column("Target")
        table.add_column("Date")
        table.add_column("Findings", justify="right")
        table.add_column("Risk Level")

        for s in scans:
            scan_id = s["scan_id"][:12]
            target_img = s.get("target_image", "")
            date = s.get("started_at", "")[:19]
            findings = str(s.get("total_findings", 0))
            risk = s.get("overall_risk_level", "unknown")
            table.add_row(scan_id, target_img, date, findings, risk)

        console.print(table)
    finally:
        history.close()


@scan_app.command("show")
def scan_show(
    scan_id: str = typer.Argument(..., help="Scan ID (or prefix) to display."),
) -> None:
    """Show detailed information about a specific scan."""
    from aisec.core.history import ScanHistory

    history = ScanHistory()
    try:
        scan = history.get_scan(scan_id)
        if not scan:
            # Try prefix match
            all_scans = history.list_scans(limit=500)
            matches = [s for s in all_scans if s["scan_id"].startswith(scan_id)]
            if len(matches) == 1:
                scan = matches[0]
                scan_id = scan["scan_id"]
            elif len(matches) > 1:
                console.print(f"[warning]Multiple scans match prefix '{scan_id}':[/warning]")
                for m in matches:
                    console.print(f"  {m['scan_id'][:12]}  {m.get('target_image', '')}")
                return
            else:
                console.print(f"[error]Scan not found:[/error] {scan_id}")
                raise typer.Exit(code=1)

        findings = history.get_findings(scan_id)

        info_text = (
            f"[bold]Scan ID:[/bold]      {scan['scan_id']}\n"
            f"[bold]Target:[/bold]       {scan.get('target_image', '')}\n"
            f"[bold]Started:[/bold]      {scan.get('started_at', '')}\n"
            f"[bold]Duration:[/bold]     {scan.get('duration_seconds', 0):.1f}s\n"
            f"[bold]Findings:[/bold]     {scan.get('total_findings', 0)}\n"
            f"[bold]Risk Level:[/bold]   {scan.get('overall_risk_level', 'unknown')}\n"
            f"[bold]Risk Score:[/bold]   {scan.get('ai_risk_score', 0):.1f}\n"
            f"[bold]Compliance:[/bold]   {scan.get('compliance_score', 0):.0f}%\n"
            f"[bold]Critical:[/bold]     {scan.get('critical_count', 0)}\n"
            f"[bold]High:[/bold]         {scan.get('high_count', 0)}\n"
            f"[bold]Medium:[/bold]       {scan.get('medium_count', 0)}\n"
            f"[bold]Low:[/bold]          {scan.get('low_count', 0)}"
        )
        console.print(Panel(info_text, title=f"Scan {scan_id[:12]}", style="info"))

        if findings:
            ftable = Table(title=f"Findings ({len(findings)})")
            ftable.add_column("Severity", style="bold")
            ftable.add_column("Agent")
            ftable.add_column("Title")
            ftable.add_column("Status")

            for f in findings:
                ftable.add_row(
                    f.get("severity", ""),
                    f.get("agent", ""),
                    f.get("title", "")[:60],
                    f.get("status", ""),
                )
            console.print(ftable)
    finally:
        history.close()


@scan_app.command("compare")
def scan_compare(
    scan_a: str = typer.Argument(..., help="Previous scan ID."),
    scan_b: str = typer.Argument(..., help="Current scan ID."),
) -> None:
    """Compare two scans to show new and resolved findings."""
    from aisec.core.history import ScanHistory

    history = ScanHistory()
    try:
        new_findings = history.get_new_findings(scan_b, scan_a)
        resolved_findings = history.get_resolved_findings(scan_b, scan_a)

        if new_findings:
            table = Table(title=f"New Findings ({len(new_findings)})", style="error")
            table.add_column("Severity")
            table.add_column("Agent")
            table.add_column("Title")
            for f in new_findings:
                table.add_row(f.get("severity", ""), f.get("agent", ""), f.get("title", "")[:60])
            console.print(table)
        else:
            console.print("[success]No new findings.[/success]")

        if resolved_findings:
            table = Table(title=f"Resolved Findings ({len(resolved_findings)})", style="success")
            table.add_column("Severity")
            table.add_column("Agent")
            table.add_column("Title")
            for f in resolved_findings:
                table.add_row(f.get("severity", ""), f.get("agent", ""), f.get("title", "")[:60])
            console.print(table)
        else:
            console.print("[dim]No resolved findings.[/dim]")

        console.print(
            f"\n[info]Summary: +{len(new_findings)} new, -{len(resolved_findings)} resolved[/info]"
        )
    finally:
        history.close()


@scan_app.command("export")
def scan_export(
    scan_id: str = typer.Argument(..., help="Scan ID to export."),
    fmt: str = typer.Option(
        "json", "--format", "-f", help="Export format (json, csv, md)."
    ),
    output: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--output", "-o", help="Output file path (default: stdout)."
    ),
) -> None:
    """Export scan findings to a file."""
    import json as json_mod
    from aisec.core.history import ScanHistory

    history = ScanHistory()
    try:
        findings = history.get_findings(scan_id)
        scan = history.get_scan(scan_id)
        if not scan:
            console.print(f"[error]Scan not found:[/error] {scan_id}")
            raise typer.Exit(code=1)

        fmt = fmt.strip().lower()

        if fmt == "json":
            content = json_mod.dumps(findings, indent=2, ensure_ascii=False)
        elif fmt == "csv":
            import csv
            import io
            buf = io.StringIO()
            if findings:
                writer = csv.DictWriter(buf, fieldnames=list(findings[0].keys()))
                writer.writeheader()
                writer.writerows(findings)
            content = buf.getvalue()
        elif fmt == "md":
            lines = [f"# Scan Findings: {scan_id[:12]}", ""]
            lines.append(f"**Target:** {scan.get('target_image', '')}")
            lines.append(f"**Date:** {scan.get('started_at', '')}")
            lines.append(f"**Total Findings:** {len(findings)}")
            lines.append("")
            lines.append("| Severity | Agent | Title | Status |")
            lines.append("|----------|-------|-------|--------|")
            for f in findings:
                lines.append(
                    f"| {f.get('severity', '')} | {f.get('agent', '')} "
                    f"| {f.get('title', '')} | {f.get('status', '')} |"
                )
            content = "\n".join(lines) + "\n"
        else:
            console.print(f"[error]Unsupported format:[/error] {fmt}")
            raise typer.Exit(code=1)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            console.print(f"[success]Exported {len(findings)} findings to {output}[/success]")
        else:
            console.print(content)
    finally:
        history.close()
