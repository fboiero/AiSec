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
    from aisec.plugins.loader import discover_plugins

    plugins = discover_plugins()

    table = Table(title=f"Installed Plugins ({len(plugins)})")
    table.add_column("Name", style="bold")
    table.add_column("Version")
    table.add_column("Description")

    if not plugins:
        console.print(table)
        console.print(
            "[dim]No plugins installed. Plugins are discovered via the "
            "'aisec.plugins' entry point group.[/dim]"
        )
        return

    for plugin in plugins:
        desc = getattr(plugin, "description", "")
        if len(desc) > 60:
            desc = desc[:57] + "..."
        table.add_row(
            getattr(plugin, "name", "unknown"),
            getattr(plugin, "version", "?"),
            desc,
        )

    console.print(table)
    console.print("[info]Use [bold]aisec plugins info <name>[/bold] for details.[/info]")


@plugins_app.command()
def info(
    name: str = typer.Argument(..., help="Plugin name to inspect."),
) -> None:
    """Show detailed information about a specific plugin."""
    from aisec.plugins.loader import discover_plugins

    plugins = discover_plugins()
    match = None
    for plugin in plugins:
        if getattr(plugin, "name", "") == name:
            match = plugin
            break

    if match is None:
        console.print(f"[error]Plugin not found:[/error] {name}")
        console.print("[info]Use [bold]aisec plugins list[/bold] to see installed plugins.[/info]")
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold]{match.name}[/bold]\n\n"
            f"  Version     : {match.version}\n"
            f"  Description : {match.description}",
            title=f"Plugin: {name}",
            style="agent",
        )
    )
