"""``aisec serve`` command -- REST API server for programmatic access.

Provides a Django REST Framework-based HTTP API for running scans,
retrieving results, and monitoring scan status. Designed for CI/CD
integration and enterprise automation.

Requires: ``pip install aisec[api]`` (django, djangorestframework).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import typer

from aisec.cli.console import console

logger = logging.getLogger(__name__)

serve_app = typer.Typer(help="Start the AiSec REST API server.")


# ---------------------------------------------------------------------------
# In-memory scan store (SQLite upgrade in future iteration)
# ---------------------------------------------------------------------------

_scan_store: dict[str, dict[str, Any]] = {}
_start_time = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Background scan runner (thread-based for Django's sync views)
# ---------------------------------------------------------------------------

def _run_scan_in_thread(scan_id: str, image: str, agents: list[str],
                        skip_agents: list[str], formats: list[str],
                        language: str) -> None:
    """Execute a scan in a background thread and store results."""
    from aisec.core.config import AiSecConfig
    from aisec.core.context import ScanContext
    from aisec.agents.orchestrator import Orchestrator
    from aisec.agents.registry import default_registry, register_core_agents
    from aisec.docker_.manager import DockerManager
    from aisec.reports.builder import ReportBuilder

    _scan_store[scan_id]["status"] = "running"
    _scan_store[scan_id]["started_at"] = datetime.now(timezone.utc).isoformat()

    try:
        config = AiSecConfig(
            agents=agents,
            skip_agents=skip_agents,
            output_formats=formats,
            language=language,
        )

        ctx = ScanContext(target_image=image, config=config)
        register_core_agents()

        dm = DockerManager(image=image)
        dm.start()
        ctx.docker_manager = dm
        ctx.container_id = dm.container_id

        try:
            orch = Orchestrator(ctx, default_registry)
            asyncio.run(orch.run_all())
        finally:
            dm.stop()

        builder = ReportBuilder(ctx)
        report = builder.build()

        report_dict = asdict(report)

        _scan_store[scan_id]["status"] = "completed"
        _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_store[scan_id]["report"] = report_dict
        _scan_store[scan_id]["finding_count"] = report.executive_summary.total_findings

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        _scan_store[scan_id]["status"] = "failed"
        _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_store[scan_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# Django configuration (minimal, self-contained)
# ---------------------------------------------------------------------------

def _configure_django() -> None:
    """Configure Django settings programmatically for standalone API use."""
    import django
    from django.conf import settings

    if settings.configured:
        return

    settings.configure(
        DEBUG=False,
        SECRET_KEY=os.environ.get("AISEC_SECRET_KEY", "aisec-dev-key-change-in-production"),
        ROOT_URLCONF="aisec.cli.serve",
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "rest_framework",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        REST_FRAMEWORK={
            "DEFAULT_RENDERER_CLASSES": [
                "rest_framework.renderers.JSONRenderer",
                "rest_framework.renderers.BrowsableAPIRenderer",
            ],
            "DEFAULT_PARSER_CLASSES": [
                "rest_framework.parsers.JSONParser",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.AllowAny",
            ],
            "UNAUTHENTICATED_USER": None,
            "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.openapi.AutoSchema",
        },
        MIDDLEWARE=[
            "aisec.cli.serve.CorsMiddleware",
        ],
        ALLOWED_HOSTS=["*"],
        USE_TZ=True,
    )
    django.setup()


# ---------------------------------------------------------------------------
# CORS Middleware (simple, standalone)
# ---------------------------------------------------------------------------

class CorsMiddleware:
    """Minimal CORS middleware that allows all origins."""

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        response = self.get_response(request)
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        if request.method == "OPTIONS":
            response.status_code = 200
            response.content = b""
        return response


# ---------------------------------------------------------------------------
# DRF Serializers
# ---------------------------------------------------------------------------

def _get_serializers() -> dict[str, Any]:
    """Lazily import and return DRF serializer classes."""
    from rest_framework import serializers

    class ScanRequestSerializer(serializers.Serializer):
        image = serializers.CharField(
            help_text="Docker image to scan (e.g. 'myapp:latest')")
        agents = serializers.ListField(
            child=serializers.CharField(), default=["all"],
            help_text="Agents to run")
        skip_agents = serializers.ListField(
            child=serializers.CharField(), default=[],
            help_text="Agents to skip")
        formats = serializers.ListField(
            child=serializers.CharField(), default=["json"],
            help_text="Output formats")
        language = serializers.CharField(
            default="en", help_text="Report language (en/es)")

    class ScanStatusSerializer(serializers.Serializer):
        scan_id = serializers.CharField()
        status = serializers.CharField()
        image = serializers.CharField()
        started_at = serializers.CharField(allow_null=True, default=None)
        completed_at = serializers.CharField(allow_null=True, default=None)
        finding_count = serializers.IntegerField(default=0)
        error = serializers.CharField(allow_null=True, default=None)

    class ScanResultSerializer(serializers.Serializer):
        scan_id = serializers.CharField()
        status = serializers.CharField()
        image = serializers.CharField()
        started_at = serializers.CharField(allow_null=True, default=None)
        completed_at = serializers.CharField(allow_null=True, default=None)
        report = serializers.DictField(allow_null=True, default=None)
        error = serializers.CharField(allow_null=True, default=None)

    class HealthSerializer(serializers.Serializer):
        status = serializers.CharField()
        version = serializers.CharField()
        agents = serializers.IntegerField()
        uptime_seconds = serializers.FloatField()

    return {
        "ScanRequestSerializer": ScanRequestSerializer,
        "ScanStatusSerializer": ScanStatusSerializer,
        "ScanResultSerializer": ScanResultSerializer,
        "HealthSerializer": HealthSerializer,
    }


# ---------------------------------------------------------------------------
# DRF Views
# ---------------------------------------------------------------------------

def _get_views() -> dict[str, Any]:
    """Lazily import and return DRF view classes."""
    from rest_framework import status
    from rest_framework.decorators import api_view
    from rest_framework.response import Response

    serializers = _get_serializers()
    ScanRequestSerializer = serializers["ScanRequestSerializer"]
    ScanStatusSerializer = serializers["ScanStatusSerializer"]
    ScanResultSerializer = serializers["ScanResultSerializer"]
    HealthSerializer = serializers["HealthSerializer"]

    @api_view(["GET"])
    def health_check(request: Any) -> Response:
        """Check API server health and version."""
        import aisec
        from aisec.agents.registry import default_registry, register_core_agents
        register_core_agents()
        uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
        data = {
            "status": "healthy",
            "version": aisec.__version__,
            "agents": len(default_registry.get_all()),
            "uptime_seconds": round(uptime, 1),
        }
        serializer = HealthSerializer(data)
        return Response(serializer.data)

    @api_view(["POST"])
    def create_scan(request: Any) -> Response:
        """Submit a new security scan.

        The scan runs asynchronously in a background thread.
        Use GET /api/scan/{scan_id}/ to poll for results.
        """
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated = serializer.validated_data
        scan_id = str(uuid.uuid4())
        _scan_store[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "image": validated["image"],
            "started_at": None,
            "completed_at": None,
            "finding_count": 0,
            "report": None,
            "error": None,
        }

        t = threading.Thread(
            target=_run_scan_in_thread,
            args=(
                scan_id,
                validated["image"],
                validated.get("agents", ["all"]),
                validated.get("skip_agents", []),
                validated.get("formats", ["json"]),
                validated.get("language", "en"),
            ),
            daemon=True,
        )
        t.start()

        result = ScanStatusSerializer({
            "scan_id": scan_id,
            "status": "pending",
            "image": validated["image"],
        })
        return Response(result.data, status=status.HTTP_201_CREATED)

    @api_view(["GET"])
    def get_scan(request: Any, scan_id: str) -> Response:
        """Retrieve scan status and results."""
        if scan_id not in _scan_store:
            return Response(
                {"detail": f"Scan {scan_id} not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        entry = _scan_store[scan_id]
        data = {
            "scan_id": entry["scan_id"],
            "status": entry["status"],
            "image": entry["image"],
            "started_at": entry.get("started_at"),
            "completed_at": entry.get("completed_at"),
            "report": entry.get("report") if entry["status"] == "completed" else None,
            "error": entry.get("error"),
        }
        serializer = ScanResultSerializer(data)
        return Response(serializer.data)

    @api_view(["GET"])
    def list_scans(request: Any) -> Response:
        """List all scans and their statuses."""
        scans = [
            {
                "scan_id": e["scan_id"],
                "status": e["status"],
                "image": e["image"],
                "started_at": e.get("started_at"),
                "completed_at": e.get("completed_at"),
                "finding_count": e.get("finding_count", 0),
                "error": e.get("error"),
            }
            for e in _scan_store.values()
        ]
        serializer = ScanStatusSerializer(scans, many=True)
        return Response(serializer.data)

    @api_view(["DELETE"])
    def delete_scan(request: Any, scan_id: str) -> Response:
        """Delete a completed or failed scan from the store."""
        if scan_id not in _scan_store:
            return Response(
                {"detail": f"Scan {scan_id} not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        entry = _scan_store[scan_id]
        if entry["status"] == "running":
            return Response(
                {"detail": "Cannot delete a running scan"},
                status=status.HTTP_409_CONFLICT,
            )
        del _scan_store[scan_id]
        return Response(
            {"detail": f"Scan {scan_id} deleted"},
            status=status.HTTP_200_OK,
        )

    return {
        "health_check": health_check,
        "create_scan": create_scan,
        "get_scan": get_scan,
        "list_scans": list_scans,
        "delete_scan": delete_scan,
    }


# ---------------------------------------------------------------------------
# URL Configuration (used as ROOT_URLCONF)
# ---------------------------------------------------------------------------

def _build_urlpatterns() -> list[Any]:
    """Build Django URL patterns for the API."""
    from django.urls import path

    views = _get_views()
    return [
        path("api/health/", views["health_check"], name="health"),
        path("api/scan/", views["create_scan"], name="create-scan"),
        path("api/scan/<str:scan_id>/", views["get_scan"], name="get-scan"),
        path("api/scans/", views["list_scans"], name="list-scans"),
        path("api/scan/<str:scan_id>/delete/", views["delete_scan"], name="delete-scan"),
    ]


# This is resolved by Django via ROOT_URLCONF = "aisec.cli.serve"
# We use a lazy property so Django is configured before URL resolution.
def _get_urlpatterns() -> list[Any]:
    _configure_django()
    return _build_urlpatterns()


class _LazyUrlpatterns:
    """Descriptor that lazily builds urlpatterns on first access."""

    def __init__(self) -> None:
        self._patterns: list[Any] | None = None

    def __iter__(self) -> Any:
        if self._patterns is None:
            self._patterns = _get_urlpatterns()
        return iter(self._patterns)

    def __len__(self) -> int:
        if self._patterns is None:
            self._patterns = _get_urlpatterns()
        return len(self._patterns)


urlpatterns = _LazyUrlpatterns()


# ---------------------------------------------------------------------------
# WSGI application factory
# ---------------------------------------------------------------------------

def get_wsgi_application() -> Any:
    """Create and return the Django WSGI application."""
    _configure_django()
    from django.core.wsgi import get_wsgi_application as django_wsgi
    return django_wsgi()


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@serve_app.callback(invoke_without_command=True)
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
) -> None:
    """Start the AiSec REST API server (Django REST Framework).

    Requires: pip install aisec[api]

    The API provides endpoints for:
      - POST /api/scan/          -- Submit a new security scan
      - GET  /api/scan/{id}/     -- Retrieve scan results
      - GET  /api/scans/         -- List all scans
      - DELETE /api/scan/{id}/delete/ -- Delete a scan
      - GET  /api/health/        -- Health check

    The browsable API is available at each endpoint in the browser.
    """
    try:
        import django
        import rest_framework
    except ImportError:
        console.print(
            "[red]Django and Django REST Framework are required for the API server.[/red]\n"
            "Install with: [bold]pip install aisec\\[api][/bold]"
        )
        raise typer.Exit(code=1)

    _configure_django()

    console.print(
        f"[bold cyan]AiSec API Server[/bold cyan] (Django REST Framework) starting on "
        f"[bold]http://{host}:{port}[/bold]"
    )
    console.print(f"  API root:     http://{host}:{port}/api/")
    console.print(f"  Health:       http://{host}:{port}/api/health/")
    console.print(f"  Submit scan:  POST http://{host}:{port}/api/scan/")
    console.print(f"  List scans:   http://{host}:{port}/api/scans/")
    console.print()

    try:
        import gunicorn  # noqa: F401
        _run_with_gunicorn(host, port, workers)
    except ImportError:
        _run_with_django_dev(host, port)


def _run_with_gunicorn(host: str, port: int, workers: int) -> None:
    """Run using gunicorn (production)."""
    from gunicorn.app.base import BaseApplication

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
