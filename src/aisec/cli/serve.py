"""``aisec serve`` command -- REST API server for programmatic access.

Provides a Django REST Framework-based HTTP API for running scans,
retrieving results, and monitoring scan status. Designed for CI/CD
integration and enterprise automation.

Requires: ``pip install aisec[api]`` (django, djangorestframework).

All API logic lives in :mod:`aisec.api`. This module is a thin CLI wrapper.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Optional

import typer

from aisec.cli.console import console

serve_app = typer.Typer(help="Start the AiSec REST API server.")

# Re-export for backward compatibility with dashboard and test imports
from aisec.api.scan_runner import (  # noqa: E402, F401
    _get_history,
    _get_executor,
    _run_scan_in_thread,
    _scan_futures,
    _graceful_shutdown,
    _start_time,
)
from aisec.api.middleware import CorsMiddleware  # noqa: E402, F401
from aisec.api.auth import ApiKeyAuthentication  # noqa: E402, F401
from aisec.api.throttle import SimpleRateThrottle, _parse_rate_limit  # noqa: E402, F401
from aisec.api.config import _configure_django  # noqa: E402, F401


@serve_app.callback(invoke_without_command=True)
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
    dashboard: bool = typer.Option(True, "--dashboard/--no-dashboard", help="Enable web dashboard UI"),
    schedule: str = typer.Option("", "--schedule", help="Cron expression for recurring scans"),
    schedule_image: str = typer.Option("", "--schedule-image", help="Docker image for scheduled scans"),
) -> None:
    """Start the AiSec REST API server (Django REST Framework).

    Requires: pip install aisec[api]
    """
    try:
        import django  # noqa: F401
        import rest_framework  # noqa: F401
    except ImportError:
        console.print(
            "[red]Django and Django REST Framework are required for the API server.[/red]\n"
            "Install with: [bold]pip install aisec\\[api][/bold]"
        )
        raise typer.Exit(code=1)

    os.environ["_AISEC_DASHBOARD_ENABLED"] = "1" if dashboard else "0"

    _configure_django()

    from aisec.utils.logging import setup_logging as _setup_logging
    log_fmt = os.environ.get("AISEC_LOG_FORMAT", "human")
    _setup_logging(level="INFO", json_format=(log_fmt == "json"))

    console.print(
        f"[bold cyan]AiSec API Server[/bold cyan] (Django REST Framework) starting on "
        f"[bold]http://{host}:{port}[/bold]"
    )
    console.print(f"  API root:     http://{host}:{port}/api/")
    console.print(f"  Health:       http://{host}:{port}/api/health/")
    console.print(f"  Readiness:    http://{host}:{port}/api/ready/")
    console.print(f"  Liveness:     http://{host}:{port}/api/live/")
    console.print(f"  API Docs:     http://{host}:{port}/api/docs/")
    console.print(f"  Metrics:      http://{host}:{port}/api/metrics/")
    console.print(f"  Submit scan:  POST http://{host}:{port}/api/scan/")
    console.print(f"  List scans:   http://{host}:{port}/api/scans/")
    console.print(f"  Audit log:    http://{host}:{port}/api/audit/")
    console.print(f"  Schedules:    http://{host}:{port}/api/schedules/")

    if dashboard:
        console.print(f"  [bold cyan]Dashboard:[/bold cyan]  http://{host}:{port}/dashboard/")
    else:
        console.print("  [dim]Dashboard:   Disabled (use --dashboard to enable)[/dim]")

    if os.environ.get("AISEC_API_KEY"):
        console.print("  [bold yellow]Auth:[/bold yellow]        API key required (X-API-Key header)")
    else:
        console.print("  [dim]Auth:        Disabled (set AISEC_API_KEY to enable)[/dim]")

    rate_limit = os.environ.get("AISEC_RATE_LIMIT", "100/min")
    console.print(f"  Rate limit:   {rate_limit}")

    # Start scheduler if --schedule is provided
    import aisec.api.scan_runner as sr
    if schedule and schedule_image:
        try:
            from aisec.core.scheduler import ScanScheduler

            def _cli_scan_callback(image: str, agents: list[str], language: str) -> None:
                scan_id = str(uuid.uuid4())
                _get_history().save_scan_report(
                    scan_id, target_image=image, image=image
                )
                executor = _get_executor()
                future = executor.submit(
                    _run_scan_in_thread,
                    scan_id, image, agents, [], ["json"], language,
                )
                _scan_futures[scan_id] = future

            sr._scheduler_instance = ScanScheduler(scan_callback=_cli_scan_callback)
            sr._scheduler_instance.add_schedule(image=schedule_image, cron=schedule)
            sr._scheduler_instance.start()
            console.print(f"  [bold green]Scheduler:[/bold green]  {schedule} → {schedule_image}")
        except Exception as exc:
            console.print(f"  [bold red]Scheduler:[/bold red]  Failed: {exc}")
    elif schedule:
        console.print("  [yellow]Scheduler: --schedule-image required with --schedule[/yellow]")

    console.print()

    try:
        import gunicorn  # noqa: F401
        _run_with_gunicorn(host, port, workers)
    except ImportError:
        _run_with_django_dev(host, port)


def _run_with_gunicorn(host: str, port: int, workers: int) -> None:
    """Run using gunicorn (production)."""
    from gunicorn.app.base import BaseApplication
    from aisec.api.wsgi import get_wsgi_application

    class AiSecGunicorn(BaseApplication):
        def __init__(self, app: Any, options: dict[str, Any]) -> None:
            self.options = options
            self.application = app
            super().__init__()

        def load_config(self) -> None:
            for key, value in self.options.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key.lower(), value)

        def load(self) -> Any:
            return self.application

    options = {
        "bind": f"{host}:{port}",
        "workers": workers,
        "worker_class": "sync",
        "accesslog": "-",
        "errorlog": "-",
    }
    AiSecGunicorn(get_wsgi_application(), options).run()


def _run_with_django_dev(host: str, port: int) -> None:
    """Run using Django's built-in development server."""
    from django.core.management import call_command

    console.print("[dim]Using Django development server (install gunicorn for production)[/dim]\n")
    call_command("runserver", f"{host}:{port}", "--noreload")
