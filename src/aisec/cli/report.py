"""``aisec report`` command group -- report management."""

from __future__ import annotations

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
        help="Target format (html, pdf).",
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

    # Placeholder -- actual renderer will be wired in later.
    console.print("[warning]Report conversion is not yet implemented.[/warning]")


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
