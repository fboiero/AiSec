"""CORS middleware with security headers for the AiSec REST API."""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

from aisec.api.throttle import _get_throttle
from aisec.core.metrics import record_api_request
from aisec.utils.logging import bind_context, clear_context


class CorsMiddleware:
    """Minimal CORS middleware that allows all origins.

    Also injects a request ID into structlog context and records
    API request metrics.
    """

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: Any) -> Any:
        request_id = request.META.get("HTTP_X_REQUEST_ID") or str(uuid.uuid4())[:8]
        bind_context(request_id=request_id)

        req_start = time.monotonic()
        response = self.get_response(request)
        req_duration = time.monotonic() - req_start

        # CORS headers
        allowed_origins = os.environ.get("AISEC_ALLOWED_ORIGINS", "*")
        origin = request.META.get("HTTP_ORIGIN", "")
        if allowed_origins == "*":
            response["Access-Control-Allow-Origin"] = "*"
        elif origin and origin in allowed_origins.split(","):
            response["Access-Control-Allow-Origin"] = origin
            response["Vary"] = "Origin"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key, X-Request-ID"
        response["X-Request-ID"] = request_id

        # Security headers
        if os.environ.get("AISEC_SECURITY_HEADERS", "true").lower() != "false":
            response["X-Content-Type-Options"] = "nosniff"
            response["X-Frame-Options"] = "DENY"
            response["X-XSS-Protection"] = "1; mode=block"
            response["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
            )
            if request.is_secure():
                response["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Rate-limit headers
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
