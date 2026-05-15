"""Health check endpoints for Kubernetes probes.

Provides:
- ``/api/ready/`` — Readiness probe (checks SQLite + executor alive)
- ``/api/live/``  — Liveness probe (trivial alive response)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_health_views() -> dict[str, Any]:
    """Return readiness and liveness view functions."""
    from rest_framework.decorators import api_view
    from rest_framework.response import Response
    from rest_framework import status

    @api_view(["GET"])
    def readiness(request: Any) -> Response:
        """Readiness probe: checks SQLite connectivity and executor alive."""
        checks: dict[str, Any] = {}
        healthy = True

        # Check SQLite
        try:
            from aisec.core.history import ScanHistory
            h = ScanHistory()
            h.stats()
            h.close()
            checks["sqlite"] = "ok"
        except Exception as exc:
            checks["sqlite"] = f"error: {exc}"
            healthy = False

        # Check executor
        try:
            from aisec.api.scan_runner import _get_executor
            executor = _get_executor()
            checks["executor"] = "ok" if not executor._shutdown else "shutdown"
            if executor._shutdown:
                healthy = False
        except Exception as exc:
            checks["executor"] = f"error: {exc}"
            healthy = False

        code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(
            {"status": "ready" if healthy else "not_ready", "checks": checks},
            status=code,
        )

    @api_view(["GET"])
    def liveness(request: Any) -> Response:
        """Liveness probe: trivial alive response for K8s."""
        return Response({"status": "alive"})

    return {
        "readiness": readiness,
        "liveness": liveness,
    }
