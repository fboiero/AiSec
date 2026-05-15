"""WSGI application factory for the AiSec REST API."""

from __future__ import annotations

from typing import Any

from aisec.api.config import _configure_django


def get_wsgi_application() -> Any:
    """Create and return the Django WSGI application."""
    _configure_django()
    from django.core.wsgi import get_wsgi_application as django_wsgi
    return django_wsgi()
