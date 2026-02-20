"""``aisec config`` command group -- configuration management."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.panel import Panel
from rich.syntax import Syntax

from aisec.cli.console import console
from aisec.core.config import AiSecConfig

config_app = typer.Typer(help="Configuration management.")

_DEFAULT_CONFIG = """\
# AiSec configuration file
# See https://github.com/aisec/aisec for documentation.

target:
  image: ""
  name: ""
  type: generic

scan:
  timeout: 3600
  agents:
    - all
  skip_agents: []

docker:
  host: unix:///var/run/docker.sock
  memory_limit: 2g
  cpu_limit: 1.0

report:
  format:
    - json
    - html
  language: en
  output_dir: ./aisec-reports

compliance:
  frameworks:
    - gdpr
    - ccpa
    - habeas_data

plugins:
  dirs: []
  disabled: []

logging:
  level: INFO
"""


@config_app.command()
def init(
    output: Path = typer.Option(
        Path("aisec.yaml"),
        "--output",
        "-o",
        help="Path to write the default configuration file.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite an existing file.",
    ),
) -> None:
    """Generate a default aisec.yaml configuration file."""
    if output.exists() and not force:
        console.print(
            f"[error]File already exists:[/error] {output}\n"
            "  Use [bold]--force[/bold] to overwrite."
        )
        raise typer.Exit(code=1)

    output.write_text(_DEFAULT_CONFIG, encoding="utf-8")
    console.print(f"[success]Configuration written to [bold]{output}[/bold][/success]")


@config_app.command()
def show(
    config: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--config",
        "-c",
        help="Path to aisec.yaml. Defaults to ./aisec.yaml.",
    ),
) -> None:
    """Display the resolved configuration."""
    config_path = config or Path("aisec.yaml")

    if config_path.exists():
        cfg = AiSecConfig.from_yaml(config_path)
    else:
        console.print(
            f"[warning]No config file found at {config_path}; showing defaults.[/warning]"
        )
        cfg = AiSecConfig()

    rendered = yaml.dump(cfg.model_dump(), default_flow_style=False, sort_keys=False)
    syntax = Syntax(rendered, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Resolved Configuration", style="info"))


@config_app.command()
def validate(
    config: Path = typer.Argument(
        ...,
        help="Path to the aisec.yaml file to validate.",
    ),
) -> None:
    """Validate an aisec.yaml configuration file."""
    if not config.exists():
        console.print(f"[error]File not found:[/error] {config}")
        raise typer.Exit(code=1)

    try:
        cfg = AiSecConfig.from_yaml(config)
    except Exception as exc:
        console.print(f"[error]Validation failed:[/error] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[success]Configuration is valid:[/success] {config}")

    # Quick sanity checks
    warnings: list[str] = []
    if not cfg.target_image:
        warnings.append("target.image is empty -- you will need to provide it at scan time.")
    if not cfg.compliance_frameworks:
        warnings.append("No compliance frameworks configured.")

    for warn in warnings:
        console.print(f"  [warning]Warning:[/warning] {warn}")
