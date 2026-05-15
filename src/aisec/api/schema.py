"""OpenAPI schema generation and Swagger UI for the AiSec REST API."""

from __future__ import annotations

from typing import Any


def _get_schema_views() -> dict[str, Any]:
    """Return view functions for OpenAPI schema and Swagger UI."""
    from rest_framework.decorators import api_view
    from rest_framework.response import Response
    from django.http import HttpResponse

    @api_view(["GET"])
    def schema_json(request: Any) -> Response:
        """Return the OpenAPI 3.0 JSON schema."""
        from rest_framework.schemas.openapi import SchemaGenerator
        import aisec

        generator = SchemaGenerator(title="AiSec API", url="/api/")
        schema = generator.get_schema(request=request)
        if schema is None:
            schema = {}
        schema.setdefault("info", {})
        schema["info"]["version"] = aisec.__version__
        schema["info"]["description"] = (
            "REST API for AiSec — deep security analysis framework for autonomous AI agents."
        )
        return Response(schema)

    @api_view(["GET"])
    def swagger_ui(request: Any) -> HttpResponse:
        """Serve a Swagger UI page pointing at /api/schema/."""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AiSec API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/schema/',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
    });
  </script>
</body>
</html>"""
        return HttpResponse(html, content_type="text/html")

    return {
        "schema_json": schema_json,
        "swagger_ui": swagger_ui,
    }
