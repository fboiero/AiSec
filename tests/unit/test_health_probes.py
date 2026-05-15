"""Tests for health probes (Phase 7)."""

from __future__ import annotations

import unittest

try:
    import rest_framework  # noqa: F401
    HAS_DRF = True
except ImportError:
    HAS_DRF = False


class TestHealthProbeModule(unittest.TestCase):
    """Verify health probe module structure."""

    def test_health_module_importable(self):
        from aisec.api.health import _get_health_views
        self.assertTrue(callable(_get_health_views))

    @unittest.skipUnless(HAS_DRF, "DRF not installed")
    def test_health_views_returned(self):
        from aisec.api.health import _get_health_views
        views = _get_health_views()
        self.assertIn("readiness", views)
        self.assertIn("liveness", views)

    @unittest.skipUnless(HAS_DRF, "DRF not installed")
    def test_health_views_are_callable(self):
        from aisec.api.health import _get_health_views
        views = _get_health_views()
        self.assertTrue(callable(views["readiness"]))
        self.assertTrue(callable(views["liveness"]))


class TestPaginationHelper(unittest.TestCase):
    """Verify pagination envelope helper."""

    def test_paginate_basic(self):
        from aisec.api.views import _paginate
        result = _paginate([1, 2, 3], page=1, page_size=20, total=3)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["page"], 1)
        self.assertEqual(result["page_size"], 20)
        self.assertFalse(result["has_more"])
        self.assertEqual(result["results"], [1, 2, 3])

    def test_paginate_has_more(self):
        from aisec.api.views import _paginate
        result = _paginate([1, 2], page=1, page_size=2, total=10)
        self.assertTrue(result["has_more"])

    def test_paginate_last_page(self):
        from aisec.api.views import _paginate
        result = _paginate([9, 10], page=5, page_size=2, total=10)
        self.assertFalse(result["has_more"])

    def test_paginate_empty(self):
        from aisec.api.views import _paginate
        result = _paginate([], page=1, page_size=20, total=0)
        self.assertEqual(result["total"], 0)
        self.assertFalse(result["has_more"])
        self.assertEqual(result["results"], [])


if __name__ == "__main__":
    unittest.main()
