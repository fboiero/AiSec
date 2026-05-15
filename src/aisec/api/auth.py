"""API key authentication for the AiSec REST API.

Checks for the API key in the ``X-API-Key`` header or the ``api_key``
query parameter.  If the ``AISEC_API_KEY`` environment variable is
not set, authentication is silently skipped.
"""

from __future__ import annotations

import os
from typing import Any


class ApiKeyAuthentication:
    """Simple API key authentication via header or query param."""

    def authenticate(self, request: Any) -> tuple[Any, str] | None:
        """Return a two-tuple of (user, auth) or *None* to skip."""
        expected = os.environ.get("AISEC_API_KEY")
        if not expected:
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

        return ({"api_key": "authenticated"}, api_key)

    def authenticate_header(self, request: Any) -> str:
        """Return a string for the WWW-Authenticate header."""
        return "X-API-Key"
