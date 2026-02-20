"""``aisec plugins`` command group -- plugin management."""

from __future__ import annotations

from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from aisec.cli.console import console

plugins_app = typer.Typer(help="Plugin management.")


@plugins_app.command("list")
def list_plugins(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed plugin information.",
    ),
) -> None:
    """List all installed AiSec plugins."""
    # Placeholder -- real implementation will query the plugin registry.
    table = Table(title="Installed Plugins")
    table.add_column("Name", style="bold")
    table.add_column("Version")
    table.add_column("Type")
    table.add_column("Status", style="success")

    # Example built-in entries (will be replaced by dynamic discovery).
    table.add_row("prompt-injection", "0.1.0", "agent", "active")
    table.add_row("tool-abuse", "0.1.0", "agent", "active")
    table.add_row("data-exfiltration", "0.1.0", "agent", "active")

    console.print(table)
    console.print("[info]Use [bold]aisec plugins info <name>[/bold] for details.[/info]")


@plugins_app.command()
def info(
    name: str = typer.Argument(..., help="Plugin name to inspect."),
) -> None:
    """Show detailed information about a specific plugin."""
    # Placeholder -- real implementation will query the plugin registry.
    console.print(
        Panel(
            f"[bold]{name}[/bold]\n\n"
            f"  Version : 0.1.0\n"
            f"  Type    : agent\n"
            f"  Author  : AiSec Team\n"
            f"  Status  : active\n\n"
            f"  [dim]Detailed plugin metadata will be available once the "
            f"plugin registry is implemented.[/dim]",
            title=f"Plugin: {name}",
            style="agent",
        )
    )
