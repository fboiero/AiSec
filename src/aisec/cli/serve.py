"""``aisec serve`` command -- REST API server for programmatic access.

Provides a Django REST Framework-based HTTP API for running scans,
retrieving results, and monitoring scan status. Designed for CI/CD
integration and enterprise automation.

Requires: ``pip install aisec[api]`` (django, djangorestframework).
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import typer

from aisec.cli.console import console
from aisec.core.metrics import (
    record_api_request,
    record_finding,
    record_scan_start,
    record_scan_complete,
    get_metrics_text,
)
from aisec.utils.logging import bind_context, clear_context

logger = logging.getLogger(__name__)

serve_app = typer.Typer(help="Start the AiSec REST API server.")


# ---------------------------------------------------------------------------
# In-memory scan store (SQLite upgrade in future iteration)
# ---------------------------------------------------------------------------

_scan_store: dict[str, dict[str, Any]] = {}
_webhook_store: dict[str, dict[str, Any]] = {}
_start_time = datetime.now(timezone.utc)

# Scheduler singleton (initialised in serve() when --schedule is provided)
_scheduler_instance: Any = None


# ---------------------------------------------------------------------------
# Background scan runner (thread-based for Django's sync views)
# ---------------------------------------------------------------------------

def _dispatch_webhooks(event: str, payload: dict[str, Any]) -> None:
    """Send event notifications to all registered webhooks."""
    import hashlib
    import hmac
    from urllib.request import Request, urlopen

    for wh_id, wh in list(_webhook_store.items()):
        # Check event filter
        events = wh.get("events", ["scan.completed", "scan.failed"])
        if event not in events:
            continue

        url = wh["url"]
        body = json.dumps({"event": event, "payload": payload}).encode()

        headers = {"Content-Type": "application/json", "X-AiSec-Event": event}

        # Sign payload if secret is set
        secret = wh.get("secret")
        if secret:
            sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-AiSec-Signature"] = f"sha256={sig}"

        try:
            req = Request(url, data=body, headers=headers, method="POST")
            urlopen(req, timeout=10)  # noqa: S310
            logger.info("Webhook %s dispatched to %s", event, url)
        except Exception as exc:
            logger.warning("Webhook %s to %s failed: %s", event, url, exc)


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
    record_scan_start()
    _scan_start = time.monotonic()

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

        record_scan_complete(time.monotonic() - _scan_start)

        # Record per-finding metrics
        for section in getattr(report, "agent_reports", []):
            for finding in getattr(section, "findings", []):
                sev = getattr(finding, "severity", None)
                if sev:
                    record_finding(str(sev.value) if hasattr(sev, "value") else str(sev))

        # Persist to SQLite history
        try:
            from aisec.core.history import ScanHistory
            history = ScanHistory()
            history.save_scan(report)
            history.close()
        except Exception as hist_exc:
            logger.warning("Failed to save scan to history: %s", hist_exc)

        _dispatch_webhooks("scan.completed", {
            "scan_id": scan_id,
            "image": image,
            "finding_count": report.executive_summary.total_findings,
            "critical_count": report.executive_summary.critical_count,
            "high_count": report.executive_summary.high_count,
            "completed_at": _scan_store[scan_id]["completed_at"],
        })

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        _scan_store[scan_id]["status"] = "failed"
        _scan_store[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _scan_store[scan_id]["error"] = str(exc)
        record_scan_complete(time.monotonic() - _scan_start, failed=True)

        _dispatch_webhooks("scan.failed", {
            "scan_id": scan_id,
            "image": image,
            "error": str(exc),
            "completed_at": _scan_store[scan_id]["completed_at"],
        })


# ---------------------------------------------------------------------------
# Django configuration (minimal, self-contained)
# ---------------------------------------------------------------------------

def _configure_django() -> None:
    """Configure Django settings programmatically for standalone API use."""
    import django
    from django.conf import settings

    if settings.configured:
        return

    # ------------------------------------------------------------------
    # Conditionally enable API-key authentication
    # ------------------------------------------------------------------
    auth_classes: list[str] = []
    permission_classes: list[str]

    if os.environ.get("AISEC_API_KEY"):
        auth_classes.append("aisec.cli.serve.ApiKeyAuthentication")
        permission_classes = ["rest_framework.permissions.IsAuthenticated"]
    else:
        permission_classes = ["rest_framework.permissions.AllowAny"]

    # ------------------------------------------------------------------
    # Conditionally enable rate limiting
    # ------------------------------------------------------------------
    throttle_classes: list[str] = []
    if os.environ.get("AISEC_RATE_LIMIT") or os.environ.get("AISEC_API_KEY"):
        # Enable throttling when an API key or explicit rate limit is set.
        # Also enable by default -- it is harmless with the 100/min default.
        throttle_classes.append("aisec.cli.serve.SimpleRateThrottle")

    rest_config: dict[str, Any] = {
        "DEFAULT_RENDERER_CLASSES": [
            "rest_framework.renderers.JSONRenderer",
            "rest_framework.renderers.BrowsableAPIRenderer",
        ],
        "DEFAULT_PARSER_CLASSES": [
            "rest_framework.parsers.JSONParser",
        ],
        "DEFAULT_PERMISSION_CLASSES": permission_classes,
        "UNAUTHENTICATED_USER": None,
        "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.openapi.AutoSchema",
    }

    if auth_classes:
        rest_config["DEFAULT_AUTHENTICATION_CLASSES"] = auth_classes
    if throttle_classes:
        rest_config["DEFAULT_THROTTLE_CLASSES"] = throttle_classes

    # ------------------------------------------------------------------
    # Dashboard templates and middleware
    # ------------------------------------------------------------------
    dashboard_enabled = os.environ.get("_AISEC_DASHBOARD_ENABLED", "1") == "1"

    middleware = ["aisec.cli.serve.CorsMiddleware"]
    if dashboard_enabled:
        middleware.append("django.middleware.csrf.CsrfViewMiddleware")

    from pathlib import Path
    dashboard_template_dir = str(Path(__file__).resolve().parent.parent / "dashboard" / "templates")

    templates_config = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [dashboard_template_dir] if dashboard_enabled else [],
            "APP_DIRS": False,
            "OPTIONS": {
                "context_processors": (
                    ["aisec.dashboard.context_processors.dashboard_context"]
                    if dashboard_enabled
                    else []
                ),
            },
        }
    ]

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
        REST_FRAMEWORK=rest_config,
        MIDDLEWARE=middleware,
        TEMPLATES=templates_config,
        ALLOWED_HOSTS=["*"],
        USE_TZ=True,
    )
    django.setup()


# ---------------------------------------------------------------------------
# API Key Authentication (optional, enabled via AISEC_API_KEY env var)
# ---------------------------------------------------------------------------

class ApiKeyAuthentication:
    """Simple API key authentication via header or query param.

    Checks for the API key in either the ``X-API-Key`` header or the
    ``api_key`` query parameter.  If the ``AISEC_API_KEY`` environment
    variable is not set, authentication is silently skipped so the API
    remains open for local development.
    """

    def authenticate(self, request: Any) -> tuple[Any, str] | None:
        """Return a two-tuple of (user, auth) or *None* to skip."""
        expected = os.environ.get("AISEC_API_KEY")
        if not expected:
            # No key configured -- auth disabled (open access).
            return None

        api_key = (
            request.META.get("HTTP_X_API_KEY")
            or request.query_params.get("api_key")
        )

        if not api_key:
            from rest_framework.exceptions import AuthenticationFailed
            raise AuthenticationFailed("Missing API key. Provide via X-API-Key header or api_key query parameter.")

        if api_key != expected:
            from rest_framework.exceptions import AuthenticationFailed
            raise AuthenticationFailed("Invalid API key.")

        # Return a simple user representation and the token.
        return ({"api_key": "authenticated"}, api_key)

    def authenticate_header(self, request: Any) -> str:
        """Return a string for the WWW-Authenticate header."""
        return "X-API-Key"


# ---------------------------------------------------------------------------
# Rate Limiting (in-memory, per-IP)
# ---------------------------------------------------------------------------

# Shared state for the throttle -- {ip: deque_of_timestamps}
_rate_limit_cache: dict[str, collections.deque] = {}
_rate_limit_lock = threading.Lock()


def _parse_rate_limit(value: str) -> tuple[int, int]:
    """Parse a rate-limit string like '100/min' into (num_requests, window_seconds)."""
    units = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600}
    try:
        num_str, unit = value.strip().split("/")
        num = int(num_str)
        window = units.get(unit.strip(), 60)
        return num, window
    except (ValueError, KeyError):
        return 100, 60  # default: 100/min


class SimpleRateThrottle:
    """In-memory per-IP rate limiting.

    Default: 100 requests per minute, configurable via the
    ``AISEC_RATE_LIMIT`` environment variable (e.g. ``"200/min"``,
    ``"10/s"``).
    """

    def __init__(self) -> None:
        raw = os.environ.get("AISEC_RATE_LIMIT", "100/min")
        self.num_requests, self.window = _parse_rate_limit(raw)

    def allow_request(self, request: Any, view: Any) -> bool:
        """Return *True* if the request should be allowed."""
        ip = self._get_client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window

        with _rate_limit_lock:
            if ip not in _rate_limit_cache:
                _rate_limit_cache[ip] = collections.deque()

            history = _rate_limit_cache[ip]

            # Evict expired entries.
            while history and history[0] < cutoff:
                history.popleft()

            if len(history) >= self.num_requests:
                return False

            history.append(now)
            return True

    def wait(self) -> float | None:
        """Seconds to wait before the next request is allowed (optional)."""
        return None

    def get_remaining(self, request: Any) -> tuple[int, int]:
        """Return (limit, remaining) for the given request IP."""
        ip = self._get_client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window

        with _rate_limit_lock:
            history = _rate_limit_cache.get(ip, collections.deque())
            # Count only non-expired entries.
            active = sum(1 for t in history if t >= cutoff)

        remaining = max(0, self.num_requests - active)
        return self.num_requests, remaining

    @staticmethod
    def _get_client_ip(request: Any) -> str:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


# Singleton throttle instance used by both middleware and DRF.
_throttle_instance: SimpleRateThrottle | None = None


def _get_throttle() -> SimpleRateThrottle:
    global _throttle_instance
    if _throttle_instance is None:
        _throttle_instance = SimpleRateThrottle()
    return _throttle_instance


# ---------------------------------------------------------------------------
# CORS Middleware (simple, standalone)
# ---------------------------------------------------------------------------

class CorsMiddleware:
    """Minimal CORS middleware that allows all origins.

    Also injects a request ID into structlog context and records
    API request metrics.
    """

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        # Inject request ID for structured logging traceability
        request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())[:8]
        bind_context(request_id=request_id)

        req_start = time.monotonic()
        response = self.get_response(request)
        req_duration = time.monotonic() - req_start

        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key, X-Request-ID"
        response["X-Request-ID"] = request_id

        # Inject rate-limit headers.
        throttle = _get_throttle()
        limit, remaining = throttle.get_remaining(request)
        response["X-RateLimit-Limit"] = str(limit)
        response["X-RateLimit-Remaining"] = str(remaining)

        # Record API metrics
        endpoint = request.path
        record_api_request(request.method, endpoint, response.status_code, req_duration)

        if request.method == "OPTIONS":
            response.status_code = 200
            response.content = b""

        clear_context()
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

    class WebhookSerializer(serializers.Serializer):
        url = serializers.URLField(help_text="Webhook endpoint URL")
        secret = serializers.CharField(
            required=False, default="",
            help_text="HMAC-SHA256 secret for payload signing")
        events = serializers.ListField(
            child=serializers.CharField(),
            default=["scan.completed", "scan.failed"],
            help_text="Events to subscribe to")

    class WebhookResponseSerializer(serializers.Serializer):
        webhook_id = serializers.CharField()
        url = serializers.CharField()
        events = serializers.ListField(child=serializers.CharField())

    class BatchScanRequestSerializer(serializers.Serializer):
        images = serializers.ListField(
            child=serializers.CharField(),
            help_text="List of Docker images to scan")
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

    return {
        "ScanRequestSerializer": ScanRequestSerializer,
        "ScanStatusSerializer": ScanStatusSerializer,
        "ScanResultSerializer": ScanResultSerializer,
        "HealthSerializer": HealthSerializer,
        "WebhookSerializer": WebhookSerializer,
        "WebhookResponseSerializer": WebhookResponseSerializer,
        "BatchScanRequestSerializer": BatchScanRequestSerializer,
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

    # -- Webhook management views -------------------------------------------

    WebhookSerializer = serializers["WebhookSerializer"]
    WebhookResponseSerializer = serializers["WebhookResponseSerializer"]
    BatchScanRequestSerializer = serializers["BatchScanRequestSerializer"]

    @api_view(["GET", "POST"])
    def webhooks(request: Any) -> Response:
        """Register or list webhook endpoints.

        POST: Register a new webhook with URL, optional secret, and event filter.
        GET: List all registered webhooks.
        """
        if request.method == "POST":
            serializer = WebhookSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            validated = serializer.validated_data
            wh_id = str(uuid.uuid4())[:8]
            _webhook_store[wh_id] = {
                "webhook_id": wh_id,
                "url": validated["url"],
                "secret": validated.get("secret", ""),
                "events": validated.get("events", ["scan.completed", "scan.failed"]),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            result = WebhookResponseSerializer({
                "webhook_id": wh_id,
                "url": validated["url"],
                "events": _webhook_store[wh_id]["events"],
            })
            return Response(result.data, status=status.HTTP_201_CREATED)

        # GET
        items = [
            {"webhook_id": wh["webhook_id"], "url": wh["url"], "events": wh["events"]}
            for wh in _webhook_store.values()
        ]
        result = WebhookResponseSerializer(items, many=True)
        return Response(result.data)

    @api_view(["DELETE"])
    def delete_webhook(request: Any, webhook_id: str) -> Response:
        """Remove a registered webhook."""
        if webhook_id not in _webhook_store:
            return Response(
                {"detail": f"Webhook {webhook_id} not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        del _webhook_store[webhook_id]
        return Response({"detail": f"Webhook {webhook_id} deleted"})

    # -- Batch scanning view -----------------------------------------------

    @api_view(["POST"])
    def batch_scan(request: Any) -> Response:
        """Submit multiple images for scanning in parallel.

        Each image is scanned independently with the same configuration.
        Returns a list of scan IDs for polling.
        """
        serializer = BatchScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated = serializer.validated_data
        images = validated["images"]
        if not images:
            return Response(
                {"detail": "At least one image is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan_ids = []
        for image in images:
            scan_id = str(uuid.uuid4())
            _scan_store[scan_id] = {
                "scan_id": scan_id,
                "status": "pending",
                "image": image,
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
                    image,
                    validated.get("agents", ["all"]),
                    validated.get("skip_agents", []),
                    validated.get("formats", ["json"]),
                    validated.get("language", "en"),
                ),
                daemon=True,
            )
            t.start()
            scan_ids.append({"scan_id": scan_id, "image": image})

        return Response(
            {"batch_size": len(images), "scans": scan_ids},
            status=status.HTTP_201_CREATED,
        )

    # -- Prometheus metrics endpoint ------------------------------------------

    @api_view(["GET"])
    def metrics_view(request: Any) -> Response:
        """Expose Prometheus-format metrics at /api/metrics/."""
        from django.http import HttpResponse

        body, content_type = get_metrics_text()
        return HttpResponse(body, content_type=content_type)

    # -- Scan schedule management views ----------------------------------------

    @api_view(["GET", "POST"])
    def schedules(request: Any) -> Response:
        """Manage scheduled scans.

        POST: Create a new scan schedule (cron-based).
        GET: List all active schedules.
        """
        global _scheduler_instance

        if request.method == "POST":
            data = request.data
            image = data.get("image")
            cron = data.get("cron")
            if not image or not cron:
                return Response(
                    {"detail": "Both 'image' and 'cron' fields are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Lazy-init the scheduler
            if _scheduler_instance is None:
                try:
                    from aisec.core.scheduler import ScanScheduler

                    def _scheduled_scan_callback(image: str, agents: list[str], language: str) -> None:
                        scan_id = str(uuid.uuid4())
                        _scan_store[scan_id] = {
                            "scan_id": scan_id,
                            "status": "pending",
                            "image": image,
                            "started_at": None,
                            "completed_at": None,
                            "finding_count": 0,
                            "report": None,
                            "error": None,
                        }
                        t = threading.Thread(
                            target=_run_scan_in_thread,
                            args=(scan_id, image, agents, [], ["json"], language),
                            daemon=True,
                        )
                        t.start()

                    _scheduler_instance = ScanScheduler(scan_callback=_scheduled_scan_callback)
                    _scheduler_instance.start()
                except Exception as exc:
                    return Response(
                        {"detail": f"Scheduler unavailable: {exc}"},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )

            agents = data.get("agents", ["all"])
            language = data.get("language", "en")

            try:
                entry = _scheduler_instance.add_schedule(
                    image=image, cron=cron, agents=agents, language=language
                )
            except Exception as exc:
                return Response(
                    {"detail": f"Invalid cron expression: {exc}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(entry.to_dict(), status=status.HTTP_201_CREATED)

        # GET — list schedules
        if _scheduler_instance is None:
            return Response([])
        return Response(_scheduler_instance.list_schedules())

    @api_view(["DELETE"])
    def delete_schedule(request: Any, schedule_id: str) -> Response:
        """Remove a scheduled scan."""
        global _scheduler_instance
        if _scheduler_instance is None or not _scheduler_instance.remove_schedule(schedule_id):
            return Response(
                {"detail": f"Schedule {schedule_id} not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"detail": f"Schedule {schedule_id} deleted"})

    return {
        "health_check": health_check,
        "create_scan": create_scan,
        "get_scan": get_scan,
        "list_scans": list_scans,
        "delete_scan": delete_scan,
        "webhooks": webhooks,
        "delete_webhook": delete_webhook,
        "batch_scan": batch_scan,
        "metrics_view": metrics_view,
        "schedules": schedules,
        "delete_schedule": delete_schedule,
    }


# ---------------------------------------------------------------------------
# URL Configuration (used as ROOT_URLCONF)
# ---------------------------------------------------------------------------

def _build_urlpatterns() -> list[Any]:
    """Build Django URL patterns for the API."""
    from django.urls import include, path

    views = _get_views()
    patterns = [
        path("api/health/", views["health_check"], name="health"),
        path("api/scan/", views["create_scan"], name="create-scan"),
        path("api/scan/batch/", views["batch_scan"], name="batch-scan"),
        path("api/scan/<str:scan_id>/", views["get_scan"], name="get-scan"),
        path("api/scans/", views["list_scans"], name="list-scans"),
        path("api/scan/<str:scan_id>/delete/", views["delete_scan"], name="delete-scan"),
        path("api/webhooks/", views["webhooks"], name="webhooks"),
        path("api/webhooks/<str:webhook_id>/", views["delete_webhook"], name="delete-webhook"),
        path("api/metrics/", views["metrics_view"], name="metrics"),
        path("api/schedules/", views["schedules"], name="schedules"),
        path("api/schedules/<str:schedule_id>/", views["delete_schedule"], name="delete-schedule"),
    ]

    if os.environ.get("_AISEC_DASHBOARD_ENABLED", "1") == "1":
        patterns.append(path("dashboard/", include("aisec.dashboard.urls")))

    return patterns


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
    dashboard: bool = typer.Option(True, "--dashboard/--no-dashboard", help="Enable web dashboard UI"),
    schedule: str = typer.Option("", "--schedule", help="Cron expression for recurring scans (e.g. '0 2 * * *', @daily)"),
    schedule_image: str = typer.Option("", "--schedule-image", help="Docker image for scheduled scans"),
) -> None:
    """Start the AiSec REST API server (Django REST Framework).

    Requires: pip install aisec[api]

    The API provides endpoints for:
      - POST /api/scan/            -- Submit a new security scan
      - POST /api/scan/batch/      -- Scan multiple images at once
      - GET  /api/scan/{id}/       -- Retrieve scan results
      - GET  /api/scans/           -- List all scans
      - DELETE /api/scan/{id}/delete/ -- Delete a scan
      - GET/POST /api/webhooks/    -- Manage webhook notifications
      - DELETE /api/webhooks/{id}/ -- Remove a webhook
      - GET  /api/health/          -- Health check
      - GET  /api/metrics/         -- Prometheus metrics
      - GET/POST /api/schedules/   -- Manage scheduled scans
      - DELETE /api/schedules/{id}/ -- Remove a schedule

    When --dashboard is enabled (default), a web UI is served at /dashboard/.

    The browsable API is available at each endpoint in the browser.

    Environment variables:
      - AISEC_API_KEY     -- Set to enable API key authentication.
                             Clients must pass the key via the X-API-Key
                             header or the ?api_key= query parameter.
                             If not set, the API allows unauthenticated access.
      - AISEC_RATE_LIMIT  -- Request rate limit per IP, e.g. "100/min",
                             "10/s", "5000/hour". Default: 100/min.
      - AISEC_SECRET_KEY  -- Django secret key (auto-generated for dev).
      - AISEC_LOG_FORMAT  -- Log format: "human" (default) or "json".
      - AISEC_LOG_JSON    -- Set to "true" for JSON log output.
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

    # Set dashboard flag before Django configuration
    os.environ["_AISEC_DASHBOARD_ENABLED"] = "1" if dashboard else "0"

    _configure_django()

    # Set up structured logging
    from aisec.utils.logging import setup_logging as _setup_logging
    log_fmt = os.environ.get("AISEC_LOG_FORMAT", "human")
    _setup_logging(level="INFO", json_format=(log_fmt == "json"))

    console.print(
        f"[bold cyan]AiSec API Server[/bold cyan] (Django REST Framework) starting on "
        f"[bold]http://{host}:{port}[/bold]"
    )
    console.print(f"  API root:     http://{host}:{port}/api/")
    console.print(f"  Health:       http://{host}:{port}/api/health/")
    console.print(f"  Metrics:      http://{host}:{port}/api/metrics/")
    console.print(f"  Submit scan:  POST http://{host}:{port}/api/scan/")
    console.print(f"  List scans:   http://{host}:{port}/api/scans/")
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
    global _scheduler_instance
    if schedule and schedule_image:
        try:
            from aisec.core.scheduler import ScanScheduler

            def _cli_scan_callback(image: str, agents: list[str], language: str) -> None:
                scan_id = str(uuid.uuid4())
                _scan_store[scan_id] = {
                    "scan_id": scan_id, "status": "pending", "image": image,
                    "started_at": None, "completed_at": None, "finding_count": 0,
                    "report": None, "error": None,
                }
                t = threading.Thread(
                    target=_run_scan_in_thread,
                    args=(scan_id, image, agents, [], ["json"], language),
                    daemon=True,
                )
                t.start()

            _scheduler_instance = ScanScheduler(scan_callback=_cli_scan_callback)
            _scheduler_instance.add_schedule(image=schedule_image, cron=schedule)
            _scheduler_instance.start()
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
