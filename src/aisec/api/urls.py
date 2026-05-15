"""URL configuration for the AiSec REST API.

Used as ROOT_URLCONF by Django.
"""

from __future__ import annotations

import os
from typing import Any

from aisec.api.config import _configure_django


def _build_urlpatterns() -> list[Any]:
    """Build Django URL patterns for the API."""
    from django.urls import include, path

    from aisec.api.views import _get_views
    from aisec.api.schema import _get_schema_views
    from aisec.api.health import _get_health_views

    views = _get_views()
    schema_views = _get_schema_views()
    health_views = _get_health_views()

    patterns = [
        path("api/health/", views["health_check"], name="health"),
        path("api/scan/", views["create_scan"], name="create-scan"),
        path("api/scan/batch/", views["batch_scan"], name="batch-scan"),
        path("api/scan/<str:scan_id>/", views["get_scan"], name="get-scan"),
        path("api/scans/", views["list_scans"], name="list-scans"),
        path("api/scan/<str:scan_id>/delete/", views["delete_scan"], name="delete-scan"),
        path("api/scans/<str:scan_id>/cancel/", views["cancel_scan"], name="cancel-scan"),
        path("api/webhooks/", views["webhooks"], name="webhooks"),
        path("api/webhooks/<str:webhook_id>/", views["delete_webhook"], name="delete-webhook"),
        path("api/metrics/", views["metrics_view"], name="metrics"),
        path("api/schedules/", views["schedules"], name="schedules"),
        path("api/schedules/<str:schedule_id>/", views["delete_schedule"], name="delete-schedule"),
        # OpenAPI / Swagger
        path("api/schema/", schema_views["schema_json"], name="schema"),
        path("api/docs/", schema_views["swagger_ui"], name="swagger-ui"),
        # Health probes
        path("api/ready/", health_views["readiness"], name="readiness"),
        path("api/live/", health_views["liveness"], name="liveness"),
        # Audit log
        path("api/audit/", views["audit_events"], name="audit-events"),
    ]

    if os.environ.get("_AISEC_DASHBOARD_ENABLED", "1") == "1":
        patterns.append(path("dashboard/", include("aisec.dashboard.urls")))

    return patterns


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
