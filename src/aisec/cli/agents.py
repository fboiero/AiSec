"""``aisec agents`` command group -- agent discovery and inspection."""

from __future__ import annotations

from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from aisec.cli.console import console

agents_app = typer.Typer(help="Agent discovery and inspection.")


@agents_app.command("list")
def list_agents(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed agent information."
    ),
) -> None:
    """List all registered security analysis agents."""
    from aisec.agents.registry import default_registry, register_core_agents

    register_core_agents()
    all_agents = default_registry.get_all()

    table = Table(title=f"Registered Agents ({len(all_agents)})")
    table.add_column("Name", style="bold")
    table.add_column("Phase")
    table.add_column("Description")
    if verbose:
        table.add_column("Frameworks")
        table.add_column("Depends On")

    for name, cls in sorted(all_agents.items()):
        phase = cls.phase.value if hasattr(cls.phase, "value") else str(cls.phase)
        desc = cls.description[:60] + "..." if len(cls.description) > 60 else cls.description
        if verbose:
            frameworks = ", ".join(cls.frameworks) if cls.frameworks else "-"
            depends = ", ".join(cls.depends_on) if cls.depends_on else "-"
            table.add_row(name, phase, desc, frameworks, depends)
        else:
            table.add_row(name, phase, desc)

    console.print(table)


@agents_app.command()
def info(
    name: str = typer.Argument(..., help="Agent name to inspect."),
) -> None:
    """Show detailed information about a specific agent."""
    from aisec.agents.registry import default_registry, register_core_agents

    register_core_agents()
    cls = default_registry.get(name)

    if cls is None:
        console.print(f"[error]Agent not found:[/error] {name}")
        console.print("[info]Use [bold]aisec agents list[/bold] to see available agents.[/info]")
        raise typer.Exit(code=1)

    phase = cls.phase.value if hasattr(cls.phase, "value") else str(cls.phase)
    frameworks = ", ".join(cls.frameworks) if cls.frameworks else "None"
    depends = ", ".join(cls.depends_on) if cls.depends_on else "None"

    console.print(
        Panel(
            f"[bold]{cls.name}[/bold]\n\n"
            f"  Class       : {cls.__name__}\n"
            f"  Phase       : {phase}\n"
            f"  Description : {cls.description}\n"
            f"  Frameworks  : {frameworks}\n"
            f"  Depends On  : {depends}",
            title=f"Agent: {name}",
            style="agent",
        )
    )
