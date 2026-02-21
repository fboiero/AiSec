"""Interactive TUI dashboard for AiSec scans using Rich Live."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import TracebackType
from typing import TYPE_CHECKING, Any

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from aisec.cli.console import console
from aisec.core.enums import Severity

if TYPE_CHECKING:
    from aisec.core.context import ScanContext
    from aisec.core.models import AgentResult, Finding

_BANNER = r"""
    _    _ ____
   / \  (_) ___|  ___  ___
  / _ \ | \___ \ / _ \/ __|
 / ___ \| |___) |  __/ (__
/_/   \_\_|____/ \___|\___|
"""

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "cyan",
}

_MAX_FINDINGS_DISPLAYED = 10


@dataclass
class _AgentStatus:
    """Internal tracker for a single agent's status."""

    name: str
    status: str = "pending"
    finding_count: int = 0
    started_at: float | None = None
    duration: float | None = None


class ScanDashboard:
    """Real-time TUI dashboard driven by ``ScanContext.event_bus`` events.

    Usage::

        async with ScanDashboard(ctx) as dash:
            await orchestrator.run_scan()

    The dashboard subscribes to ``agent.started``, ``agent.completed``, and
    ``finding.new`` events and refreshes the Rich Live display automatically.
    """

    def __init__(self, ctx: ScanContext) -> None:
        self._ctx = ctx
        self._live: Live | None = None
        self._agents: dict[str, _AgentStatus] = {}
        self._recent_findings: list[dict[str, Any]] = []
        self._total_findings = 0
        self._start_time: float = time.monotonic()
        self._overall_progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
        )
        self._progress_task_id: int | None = None

    # ── Async context manager ───────────────────────────────────────

    async def __aenter__(self) -> ScanDashboard:
        self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    # ── Public API ──────────────────────────────────────────────────

    def start(self) -> None:
        """Start the Live context and register event handlers."""
        self._start_time = time.monotonic()
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=4,
            screen=False,
        )
        self._live.start()
        self._register_handlers()

    def stop(self) -> None:
        """Stop the Live context and print a final snapshot."""
        if self._live is not None:
            # Push one last update so the final state is visible.
            self._live.update(self._build_layout())
            self._live.stop()
            self._live = None

    def update(self) -> None:
        """Manually refresh the display."""
        if self._live is not None:
            self._live.update(self._build_layout())

    # ── Event handlers ──────────────────────────────────────────────

    def _register_handlers(self) -> None:
        bus = self._ctx.event_bus
        bus.on("agent.started", self._on_agent_started)
        bus.on("agent.completed", self._on_agent_completed)
        bus.on("finding.new", self._on_finding_new)

    def _on_agent_started(self, agent_name: str, **_kwargs: Any) -> None:
        self._agents.setdefault(
            agent_name, _AgentStatus(name=agent_name)
        )
        entry = self._agents[agent_name]
        entry.status = "running"
        entry.started_at = time.monotonic()
        self.update()

    def _on_agent_completed(self, result: Any, **_kwargs: Any) -> None:
        agent_name: str = getattr(result, "agent", "unknown")
        findings = getattr(result, "findings", [])
        duration: float = getattr(result, "duration_seconds", 0.0)

        self._agents.setdefault(
            agent_name, _AgentStatus(name=agent_name)
        )
        entry = self._agents[agent_name]

        if getattr(result, "error", None):
            entry.status = "error"
        else:
            entry.status = "done"

        entry.finding_count = len(findings)
        entry.duration = duration

        # Advance overall progress bar.
        if self._progress_task_id is not None:
            self._overall_progress.advance(self._progress_task_id)

        self.update()

    def _on_finding_new(self, finding: Any, **_kwargs: Any) -> None:
        self._total_findings += 1
        severity: Severity = getattr(finding, "severity", Severity.INFO)
        self._recent_findings.append({
            "title": getattr(finding, "title", "Untitled"),
            "severity": severity,
            "agent": getattr(finding, "agent", "unknown"),
        })
        # Keep only the last N findings.
        if len(self._recent_findings) > _MAX_FINDINGS_DISPLAYED:
            self._recent_findings = self._recent_findings[-_MAX_FINDINGS_DISPLAYED:]
        self.update()

    # ── Layout builders ─────────────────────────────────────────────

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=9),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="agents", ratio=3),
            Layout(name="findings", ratio=2),
        )
        layout["header"].update(self._build_header())
        layout["agents"].update(self._build_agent_table())
        layout["findings"].update(self._build_findings_panel())
        layout["footer"].update(self._build_footer())
        return layout

    def _build_header(self) -> Panel:
        elapsed = time.monotonic() - self._start_time
        header_text = Text.from_ansi(f"{_BANNER}")
        header_text.append(
            f"  Target: {self._ctx.target_image}  |  "
            f"Scan ID: {str(self._ctx.scan_id)[:8]}  |  "
            f"Elapsed: {elapsed:.0f}s",
            style="dim",
        )
        return Panel(
            header_text,
            style="bold cyan",
            subtitle="Deep AI Agent Security Analysis",
        )

    def _build_agent_table(self) -> Panel:
        table = Table(
            title="Agent Status",
            expand=True,
            show_lines=False,
            padding=(0, 1),
        )
        table.add_column("Agent", style="bold magenta", no_wrap=True, ratio=3)
        table.add_column("Status", justify="center", no_wrap=True, ratio=2)
        table.add_column("Findings", justify="right", ratio=1)
        table.add_column("Duration", justify="right", ratio=1)

        for entry in self._agents.values():
            status_text = self._style_status(entry.status)
            duration_str = (
                f"{entry.duration:.1f}s" if entry.duration is not None else "-"
            )
            table.add_row(
                entry.name,
                status_text,
                str(entry.finding_count),
                duration_str,
            )

        # If no agents yet, show a placeholder.
        if not self._agents:
            table.add_row("Waiting for agents...", Text("--", style="dim"), "-", "-")

        return Panel(table, title="Agents", border_style="magenta")

    def _build_findings_panel(self) -> Panel:
        if not self._recent_findings:
            content = Text("No findings yet.", style="dim")
        else:
            content = Text()
            for idx, entry in enumerate(reversed(self._recent_findings)):
                severity: Severity = entry["severity"]
                style = _SEVERITY_STYLES.get(severity, "white")
                tag = severity.value.upper()
                content.append(f"[{tag:>8}] ", style=style)
                content.append(entry["title"], style="bold")
                content.append(f"  ({entry['agent']})", style="dim")
                if idx < len(self._recent_findings) - 1:
                    content.append("\n")

        return Panel(
            content,
            title=f"Live Findings ({self._total_findings} total)",
            border_style="yellow",
        )

    def _build_footer(self) -> Panel:
        done_count = sum(
            1 for a in self._agents.values() if a.status in ("done", "error")
        )
        total_count = len(self._agents) or 1  # avoid zero division

        # Lazily create / update the progress bar task.
        if self._progress_task_id is None:
            self._progress_task_id = self._overall_progress.add_task(
                "Overall progress",
                total=total_count,
                completed=done_count,
            )
        else:
            self._overall_progress.update(
                self._progress_task_id,
                total=total_count,
                completed=done_count,
            )

        error_count = sum(1 for a in self._agents.values() if a.status == "error")
        stats = Text()
        stats.append(f"  Agents: {done_count}/{total_count} complete", style="cyan")
        if error_count:
            stats.append(f"  |  Errors: {error_count}", style="bold red")
        stats.append(f"  |  Findings: {self._total_findings}", style="yellow")

        footer_layout = Layout()
        footer_layout.split_row(
            Layout(self._overall_progress, ratio=3),
            Layout(stats, ratio=2),
        )

        return Panel(footer_layout, style="dim")

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _style_status(status: str) -> Text:
        styles = {
            "pending": ("PENDING", "dim"),
            "running": ("RUNNING", "bold cyan"),
            "done": ("DONE", "bold green"),
            "error": ("ERROR", "bold red"),
        }
        label, style = styles.get(status, (status.upper(), "white"))
        return Text(label, style=style)

    def set_agent_count(self, count: int) -> None:
        """Pre-set the expected number of agents for the progress bar."""
        if self._progress_task_id is not None:
            self._overall_progress.update(self._progress_task_id, total=count)
