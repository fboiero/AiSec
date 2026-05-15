"""Django configuration for the AiSec REST API.

Provides ``_configure_django()`` which sets up Django settings
programmatically for standalone API use without a traditional
``settings.py`` module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


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
        auth_classes.append("aisec.api.auth.ApiKeyAuthentication")
        permission_classes = ["rest_framework.permissions.IsAuthenticated"]
    else:
        permission_classes = ["rest_framework.permissions.AllowAny"]

    # ------------------------------------------------------------------
    # Conditionally enable rate limiting
    # ------------------------------------------------------------------
    throttle_classes: list[str] = []
    if os.environ.get("AISEC_RATE_LIMIT") or os.environ.get("AISEC_API_KEY"):
        throttle_classes.append("aisec.api.throttle.SimpleRateThrottle")

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

    middleware = ["aisec.api.middleware.CorsMiddleware"]
    if dashboard_enabled:
        middleware.append("django.middleware.csrf.CsrfViewMiddleware")

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
        ROOT_URLCONF="aisec.api.urls",
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
