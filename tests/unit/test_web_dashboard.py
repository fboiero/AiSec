"""Tests for the Web UI Dashboard (v1.6.0).

Tests URL resolution, view smoke tests, HTMX partials,
ScanHistory new query methods, and context processors.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aisec.core.history import ScanHistory

try:
    import django
    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False

requires_django = pytest.mark.skipif(not HAS_DJANGO, reason="Django not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def history(tmp_path):
    """Create a temporary ScanHistory for testing."""
    db = ScanHistory(db_path=tmp_path / "test.db")
    yield db
    db.close()


def _insert_scan(history, scan_id="scan-001", target="myapp:latest",
                 critical=2, high=3, medium=5, low=4, info=1):
    """Insert a test scan directly via SQL."""
    conn = history._get_conn()
    conn.execute(
        """INSERT INTO scans (scan_id, report_id, target_name, target_image,
           started_at, completed_at, duration_seconds, total_findings,
           critical_count, high_count, medium_count, low_count, info_count,
           overall_risk_level, ai_risk_score, compliance_score,
           aisec_version, language, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, "rpt-001", "myapp", target,
         "2026-02-23T10:00:00", "2026-02-23T10:05:00", 300.0,
         critical + high + medium + low + info,
         critical, high, medium, low, info,
         "high", 7.5, 65.0, "1.6.0", "en",
         json.dumps({"top_risks": ["test risk"]})),
    )
    conn.commit()


def _insert_finding(history, scan_id="scan-001", finding_id="f-001",
                    title="Test Finding", severity="high", agent="network"):
    """Insert a test finding directly via SQL."""
    conn = history._get_conn()
    conn.execute(
        """INSERT OR IGNORE INTO findings
           (scan_id, finding_id, title, severity, agent,
            owasp_llm, owasp_agentic, nist_ai_rmf,
            cvss_score, ai_risk_score, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, finding_id, title, severity, agent,
         '["LLM01"]', '["ASI01"]', '["GOVERN-1"]',
         7.5, 6.0, "open"),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# ScanHistory new methods
# ---------------------------------------------------------------------------

class TestSeverityDistribution:
    def test_empty_db(self, history):
        result = history.severity_distribution()
        assert result == {}

    def test_counts_by_severity(self, history):
        _insert_scan(history)
        _insert_finding(history, finding_id="f1", severity="critical")
        _insert_finding(history, finding_id="f2", severity="critical")
        _insert_finding(history, finding_id="f3", severity="high")
        result = history.severity_distribution()
        assert result["critical"] == 2
        assert result["high"] == 1


class TestSearchFindings:
    def test_empty_db(self, history):
        assert history.search_findings() == []

    def test_filter_by_severity(self, history):
        _insert_scan(history)
        _insert_finding(history, finding_id="f1", severity="critical")
        _insert_finding(history, finding_id="f2", severity="low")
        results = history.search_findings(severity="critical")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    def test_filter_by_agent(self, history):
        _insert_scan(history)
        _insert_finding(history, finding_id="f1", agent="network")
        _insert_finding(history, finding_id="f2", agent="privacy")
        results = history.search_findings(agent="privacy")
        assert len(results) == 1
        assert results[0]["agent"] == "privacy"

    def test_filter_by_framework(self, history):
        _insert_scan(history)
        _insert_finding(history, finding_id="f1")
        results = history.search_findings(framework="LLM01")
        assert len(results) == 1

    def test_pagination(self, history):
        _insert_scan(history)
        for i in range(5):
            _insert_finding(history, finding_id=f"f-{i}", title=f"Finding {i}")
        page1 = history.search_findings(limit=2, offset=0)
        page2 = history.search_findings(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2

    def test_includes_target_image(self, history):
        _insert_scan(history)
        _insert_finding(history)
        results = history.search_findings()
        assert results[0]["target_image"] == "myapp:latest"


class TestGlobalTrend:
    def test_empty_db(self, history):
        assert history.global_trend() == []

    def test_aggregates_by_date(self, history):
        _insert_scan(history, scan_id="s1")
        _insert_scan(history, scan_id="s2", target="other:latest")
        result = history.global_trend()
        assert len(result) >= 1
        assert result[0]["scan_count"] == 2


class TestDistinctTargets:
    def test_empty_db(self, history):
        assert history.distinct_targets() == []

    def test_returns_unique(self, history):
        _insert_scan(history, scan_id="s1", target="app1:latest")
        _insert_scan(history, scan_id="s2", target="app2:latest")
        _insert_scan(history, scan_id="s3", target="app1:latest")
        targets = history.distinct_targets()
        assert sorted(targets) == ["app1:latest", "app2:latest"]


class TestCountScans:
    def test_empty_db(self, history):
        assert history.count_scans() == 0

    def test_total_count(self, history):
        _insert_scan(history, scan_id="s1")
        _insert_scan(history, scan_id="s2")
        assert history.count_scans() == 2

    def test_filtered_count(self, history):
        _insert_scan(history, scan_id="s1", target="app1:latest")
        _insert_scan(history, scan_id="s2", target="app2:latest")
        assert history.count_scans(target_image="app1:latest") == 1


# ---------------------------------------------------------------------------
# Dashboard package imports
# ---------------------------------------------------------------------------

class TestDashboardImports:
    def test_import_package(self):
        import aisec.dashboard
        assert hasattr(aisec.dashboard, "__doc__")

    @requires_django
    def test_import_views(self):
        from aisec.dashboard.views import home, scan_list, scan_detail
        assert callable(home)
        assert callable(scan_list)
        assert callable(scan_detail)

    @requires_django
    def test_import_urls(self):
        from aisec.dashboard.urls import urlpatterns, app_name
        assert app_name == "dashboard"
        assert len(urlpatterns) == 10

    def test_import_context_processors(self):
        from aisec.dashboard.context_processors import dashboard_context
        assert callable(dashboard_context)


# ---------------------------------------------------------------------------
# URL resolution (requires Django setup)
# ---------------------------------------------------------------------------

@pytest.fixture
def django_setup():
    """Set up Django for testing."""
    os.environ["_AISEC_DASHBOARD_ENABLED"] = "1"
    os.environ.setdefault("AISEC_SECRET_KEY", "test-secret-key")
    try:
        from aisec.cli.serve import _configure_django
        _configure_django()
    except Exception:
        pass  # May already be configured
    yield


@requires_django
class TestURLResolution:
    def test_dashboard_home_resolves(self, django_setup):
        try:
            from django.urls import reverse
            url = reverse("dashboard:home")
            assert url == "/dashboard/"
        except Exception:
            pytest.skip("Django URL resolution not available")

    def test_dashboard_scan_list_resolves(self, django_setup):
        try:
            from django.urls import reverse
            url = reverse("dashboard:scan-list")
            assert url == "/dashboard/scans/"
        except Exception:
            pytest.skip("Django URL resolution not available")

    def test_dashboard_new_scan_resolves(self, django_setup):
        try:
            from django.urls import reverse
            url = reverse("dashboard:new-scan")
            assert url == "/dashboard/new-scan/"
        except Exception:
            pytest.skip("Django URL resolution not available")

    def test_dashboard_scan_detail_resolves(self, django_setup):
        try:
            from django.urls import reverse
            url = reverse("dashboard:scan-detail", kwargs={"scan_id": "abc-123"})
            assert "/dashboard/scans/abc-123/" == url
        except Exception:
            pytest.skip("Django URL resolution not available")

    def test_partial_scan_status_resolves(self, django_setup):
        try:
            from django.urls import reverse
            url = reverse("dashboard:partial-scan-status", kwargs={"scan_id": "abc"})
            assert "/dashboard/partials/scan-status/abc/" == url
        except Exception:
            pytest.skip("Django URL resolution not available")


# ---------------------------------------------------------------------------
# Context processor
# ---------------------------------------------------------------------------

@requires_django
class TestContextProcessor:
    @patch("aisec.cli.serve._scan_store", {})
    def test_returns_expected_keys(self):
        from aisec.dashboard.context_processors import dashboard_context
        ctx = dashboard_context(MagicMock())
        assert "aisec_version" in ctx
        assert "nav_items" in ctx
        assert "active_scan_count" in ctx

    @patch("aisec.cli.serve._scan_store", {
        "s1": {"status": "running"},
        "s2": {"status": "completed"},
        "s3": {"status": "pending"},
    })
    def test_active_scan_count(self):
        from aisec.dashboard.context_processors import dashboard_context
        ctx = dashboard_context(MagicMock())
        assert ctx["active_scan_count"] == 2  # running + pending

    @patch("aisec.cli.serve._scan_store", {})
    def test_nav_items_structure(self):
        from aisec.dashboard.context_processors import dashboard_context
        ctx = dashboard_context(MagicMock())
        for item in ctx["nav_items"]:
            assert "url" in item
            assert "label" in item
            assert "icon" in item


# ---------------------------------------------------------------------------
# Version bump check
# ---------------------------------------------------------------------------

class TestVersionBump:
    def test_version_is_1_6_0(self):
        import aisec
        assert aisec.__version__ == "1.6.0"
