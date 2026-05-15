"""Tests for the API refactoring (Phase 1).

Verifies that the serve.py monolith was properly decomposed into the
``aisec.api`` package and that all modules are importable.
"""

from __future__ import annotations

import importlib
import os
import unittest


class TestApiPackageStructure(unittest.TestCase):
    """Verify that all API submodules exist and are importable."""

    def test_api_init_importable(self):
        mod = importlib.import_module("aisec.api")
        self.assertTrue(hasattr(mod, "__doc__"))

    def test_api_config_importable(self):
        mod = importlib.import_module("aisec.api.config")
        self.assertTrue(hasattr(mod, "_configure_django"))

    def test_api_auth_importable(self):
        mod = importlib.import_module("aisec.api.auth")
        self.assertTrue(hasattr(mod, "ApiKeyAuthentication"))

    def test_api_throttle_importable(self):
        mod = importlib.import_module("aisec.api.throttle")
        self.assertTrue(hasattr(mod, "SimpleRateThrottle"))
        self.assertTrue(hasattr(mod, "_parse_rate_limit"))

    def test_api_middleware_importable(self):
        mod = importlib.import_module("aisec.api.middleware")
        self.assertTrue(hasattr(mod, "CorsMiddleware"))

    def test_api_serializers_importable(self):
        mod = importlib.import_module("aisec.api.serializers")
        self.assertTrue(hasattr(mod, "_get_serializers"))

    def test_api_views_importable(self):
        mod = importlib.import_module("aisec.api.views")
        self.assertTrue(hasattr(mod, "_get_views"))

    def test_api_urls_importable(self):
        mod = importlib.import_module("aisec.api.urls")
        self.assertTrue(hasattr(mod, "urlpatterns"))

    def test_api_scan_runner_importable(self):
        mod = importlib.import_module("aisec.api.scan_runner")
        self.assertTrue(hasattr(mod, "_run_scan_in_thread"))
        self.assertTrue(hasattr(mod, "_get_history"))
        self.assertTrue(hasattr(mod, "_get_executor"))

    def test_api_wsgi_importable(self):
        mod = importlib.import_module("aisec.api.wsgi")
        self.assertTrue(hasattr(mod, "get_wsgi_application"))

    def test_api_schema_importable(self):
        mod = importlib.import_module("aisec.api.schema")
        self.assertTrue(hasattr(mod, "_get_schema_views"))

    def test_api_health_importable(self):
        mod = importlib.import_module("aisec.api.health")
        self.assertTrue(hasattr(mod, "_get_health_views"))


class TestServeBackwardCompatibility(unittest.TestCase):
    """Verify that serve.py re-exports key symbols for backward compat."""

    def test_serve_reexports_get_history(self):
        from aisec.cli.serve import _get_history
        self.assertIsNotNone(_get_history)

    def test_serve_reexports_get_executor(self):
        from aisec.cli.serve import _get_executor
        self.assertIsNotNone(_get_executor)

    def test_serve_reexports_run_scan_in_thread(self):
        from aisec.cli.serve import _run_scan_in_thread
        self.assertIsNotNone(_run_scan_in_thread)

    def test_serve_reexports_scan_futures(self):
        from aisec.cli.serve import _scan_futures
        self.assertIsInstance(_scan_futures, dict)


class TestThrottleParsing(unittest.TestCase):
    """Verify rate-limit parsing logic."""

    def test_parse_100_per_min(self):
        from aisec.api.throttle import _parse_rate_limit
        num, window = _parse_rate_limit("100/min")
        self.assertEqual(num, 100)
        self.assertEqual(window, 60)

    def test_parse_10_per_sec(self):
        from aisec.api.throttle import _parse_rate_limit
        num, window = _parse_rate_limit("10/s")
        self.assertEqual(num, 10)
        self.assertEqual(window, 1)

    def test_parse_5000_per_hour(self):
        from aisec.api.throttle import _parse_rate_limit
        num, window = _parse_rate_limit("5000/hour")
        self.assertEqual(num, 5000)
        self.assertEqual(window, 3600)

    def test_parse_invalid_returns_default(self):
        from aisec.api.throttle import _parse_rate_limit
        num, window = _parse_rate_limit("invalid")
        self.assertEqual(num, 100)
        self.assertEqual(window, 60)


class TestApiKeyAuth(unittest.TestCase):
    """Verify ApiKeyAuthentication logic."""

    def test_no_key_configured_returns_none(self):
        from aisec.api.auth import ApiKeyAuthentication
        auth = ApiKeyAuthentication()
        os.environ.pop("AISEC_API_KEY", None)
        result = auth.authenticate(type("R", (), {"META": {}, "query_params": {}})())
        self.assertIsNone(result)

    def test_authenticate_header(self):
        from aisec.api.auth import ApiKeyAuthentication
        auth = ApiKeyAuthentication()
        self.assertEqual(auth.authenticate_header(None), "X-API-Key")


if __name__ == "__main__":
    unittest.main()
