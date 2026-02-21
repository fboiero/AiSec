"""``aisec scan`` command -- run security analysis scans."""

from __future__ import annotations

import asyncio
import logging
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
    from aisec.reports.renderers import json_renderer, html_renderer, pdf_renderer

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
            ctx.container_id = sandbox.target.short_id if sandbox.target else None
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
            finding_count = len(getattr(result, "findings", []))
            progress.update(
                scan_task,
                advance=1,
                description=f"Agent [bold]{agent_name}[/bold] done ({finding_count} findings)",
            )

        ctx.event_bus.on("agent.completed", _on_agent_complete)

        try:
            await orchestrator.run_scan()
        except Exception as exc:
            console.print(f"[error]Scan error: {exc}[/error]")
            logger.exception("Scan failed")

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
        import logging as _logging
        _logging.basicConfig(level=_logging.DEBUG, format="%(name)s %(message)s")
        console.print(Panel(str(cfg), title="Resolved configuration", style="dim"))

    # ── Execute scan ────────────────────────────────────────────────
    ctx = asyncio.run(_run_scan(image, cfg, verbose))

    # ── Display results ─────────────────────────────────────────────
    if ctx.agent_results:
        console.print(_build_results_table(ctx))

        # Summary stats
        total_findings = sum(len(r.findings) for r in ctx.agent_results.values())
        console.print(
            f"\n[info]Total findings: [bold]{total_findings}[/bold] "
            f"across {len(ctx.agent_results)} agents[/info]"
        )
    else:
        console.print(
            Panel("[warning]No agent results produced.[/warning]", title="Results")
        )

    # ── Report paths ─────────────────────────────────────────────────
    rendered = ctx.metadata.get("rendered_files", [])
    if rendered:
        console.print("\n[success]Reports written to:[/success]")
        for path in rendered:
            console.print(f"  {path}")
    console.print()
