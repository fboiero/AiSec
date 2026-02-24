"""Tests for the Prometheus metrics module."""

from __future__ import annotations

import pytest
from unittest.mock import patch


class TestMetricsAvailability:
    """Test metrics availability detection."""

    def test_is_available_returns_bool(self):
        from aisec.core.metrics import is_available
        assert isinstance(is_available(), bool)

    def test_get_metrics_text_returns_tuple(self):
        from aisec.core.metrics import get_metrics_text
        body, content_type = get_metrics_text()
        assert isinstance(body, str)
        assert isinstance(content_type, str)


class TestMetricsRecording:
    """Test metric recording functions (no-op safe)."""

    def test_record_scan_start(self):
        from aisec.core.metrics import record_scan_start
        # Should not raise regardless of prometheus_client presence
        record_scan_start()

    def test_record_scan_complete(self):
        from aisec.core.metrics import record_scan_complete
        record_scan_complete(1.5)
        record_scan_complete(2.0, failed=True)

    def test_record_finding(self):
        from aisec.core.metrics import record_finding
        record_finding("critical")
        record_finding("high")
        record_finding("medium")
        record_finding("low")

    def test_record_agent_duration(self):
        from aisec.core.metrics import record_agent_duration
        record_agent_duration("network", 5.2)
        record_agent_duration("prompt_security", 12.0)

    def test_record_api_request(self):
        from aisec.core.metrics import record_api_request
        record_api_request("GET", "/api/health/", 200, 0.015)
        record_api_request("POST", "/api/scan/", 201, 0.5)

    def test_track_scan_context_manager(self):
        from aisec.core.metrics import track_scan
        with track_scan():
            pass  # Simulate a scan

    def test_track_scan_context_manager_on_failure(self):
        from aisec.core.metrics import track_scan
        with pytest.raises(ValueError):
            with track_scan():
                raise ValueError("simulated failure")


class TestMetricsFallback:
    """Test graceful fallback when prometheus_client is not installed."""

    def test_noop_when_not_available(self):
        """Verify all functions are safe to call even without prometheus_client."""
        from aisec.core import metrics

        # Temporarily pretend prometheus_client is not available
        original = metrics._HAS_PROMETHEUS
        try:
            metrics._HAS_PROMETHEUS = False

            # All these should be no-ops
            metrics.record_scan_start()
            metrics.record_scan_complete(1.0)
            metrics.record_finding("critical")
            metrics.record_agent_duration("test", 1.0)
            metrics.record_api_request("GET", "/", 200, 0.01)

            body, ct = metrics.get_metrics_text()
            assert "not installed" in body
        finally:
            metrics._HAS_PROMETHEUS = original

    def test_get_metrics_text_without_prometheus(self):
        from aisec.core import metrics
        original = metrics._HAS_PROMETHEUS
        try:
            metrics._HAS_PROMETHEUS = False
            body, ct = metrics.get_metrics_text()
            assert ct == "text/plain; charset=utf-8"
            assert "prometheus_client" in body
        finally:
            metrics._HAS_PROMETHEUS = original
