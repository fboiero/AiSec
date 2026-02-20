"""Typer root application for AiSec CLI."""

from __future__ import annotations

from typing import Optional

import typer

import aisec
from aisec.cli.config_cmd import config_app
from aisec.cli.plugins import plugins_app
from aisec.cli.report import report_app
from aisec.cli.scan import scan_app

app = typer.Typer(
    name="aisec",
    help="Deep security analysis for autonomous AI agent implementations.",
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"aisec {aisec.__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(  # noqa: UP007
        None,
        "--version",
        "-V",
        help="Show AiSec version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """AiSec -- Deep security analysis for autonomous AI agent implementations."""


app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(plugins_app, name="plugins")
app.add_typer(config_app, name="config")
