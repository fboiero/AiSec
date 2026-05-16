"""Tests for OpenAPI schema and Swagger UI (Phase 2)."""

from __future__ import annotations

import unittest

try:
    import rest_framework  # noqa: F401
    HAS_DRF = True
except ImportError:
    HAS_DRF = False


class TestOpenApiModule(unittest.TestCase):
    """Verify OpenAPI schema module structure."""

    def test_schema_module_importable(self):
        from aisec.api.schema import _get_schema_views
        self.assertTrue(callable(_get_schema_views))

    @unittest.skipUnless(HAS_DRF, "DRF not installed")
    def test_schema_views_returned(self):
        from aisec.api.schema import _get_schema_views
        views = _get_schema_views()
        self.assertIn("schema_json", views)
        self.assertIn("swagger_ui", views)

    @unittest.skipUnless(HAS_DRF, "DRF not installed")
    def test_schema_views_are_callable(self):
        from aisec.api.schema import _get_schema_views
        views = _get_schema_views()
        self.assertTrue(callable(views["schema_json"]))
        self.assertTrue(callable(views["swagger_ui"]))

    @unittest.skipUnless(HAS_DRF, "DRF not installed")
    def test_schema_json_includes_model_risk_endpoints(self):
        from aisec.api.config import _configure_django
        from aisec.api.schema import _get_schema_views

        _configure_django()
        from rest_framework.test import APIRequestFactory

        request = APIRequestFactory().get("/api/schema/")
        response = _get_schema_views()["schema_json"](request)
        paths = response.data.get("paths", {})

        self.assertEqual(response.status_code, 200)
        self.assertIn("/api/evaluate/model/", paths)
        self.assertIn("/api/evaluations/", paths)
        self.assertIn("/api/evaluations/rollup/", paths)
        self.assertIn("/api/evaluation-baselines/", paths)
        self.assertNotIn("/api/api/evaluate/model/", paths)


class TestUrlsIncludeSchemaEndpoints(unittest.TestCase):
    """Verify that schema/docs URL patterns are registered."""

    def test_urls_module_has_patterns(self):
        from aisec.api.urls import _LazyUrlpatterns
        self.assertTrue(hasattr(_LazyUrlpatterns, "__iter__"))
        self.assertTrue(hasattr(_LazyUrlpatterns, "__len__"))


if __name__ == "__main__":
    unittest.main()
