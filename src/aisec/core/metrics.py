"""Prometheus metrics for AiSec observability.

Provides counters, gauges, and histograms for scan operations, findings,
agent execution, and API requests. Gracefully degrades to no-ops when
``prometheus_client`` is not installed.

Install: ``pip install aisec[metrics]``
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False

# ---------------------------------------------------------------------------
# Metric definitions (only created when prometheus_client is available)
# ---------------------------------------------------------------------------

if _HAS_PROMETHEUS:
    SCANS_TOTAL = Counter(
        "aisec_scans_total",
        "Total number of scans started",
        ["status"],
    )
    SCANS_ACTIVE = Gauge(
        "aisec_scans_active",
        "Number of currently running scans",
    )
    SCAN_DURATION = Histogram(
        "aisec_scan_duration_seconds",
        "Scan duration in seconds",
        buckets=[10, 30, 60, 120, 300, 600, 1800, 3600],
    )
    FINDINGS_TOTAL = Counter(
        "aisec_findings_total",
        "Total findings by severity",
        ["severity"],
    )
    AGENT_DURATION = Histogram(
        "aisec_agent_duration_seconds",
        "Per-agent execution duration in seconds",
        ["agent"],
        buckets=[1, 5, 10, 30, 60, 120, 300],
    )
    API_REQUESTS_TOTAL = Counter(
        "aisec_api_requests_total",
        "Total API requests",
        ["method", "endpoint", "status"],
    )
    API_REQUEST_DURATION = Histogram(
        "aisec_api_request_duration_seconds",
        "API request duration in seconds",
        ["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )


# ---------------------------------------------------------------------------
# Public helpers — safe to call regardless of prometheus_client presence
# ---------------------------------------------------------------------------


def record_scan_start() -> None:
    """Record that a scan has started."""
    if not _HAS_PROMETHEUS:
        return
    SCANS_TOTAL.labels(status="started").inc()
    SCANS_ACTIVE.inc()


def record_scan_complete(duration: float, *, failed: bool = False) -> None:
    """Record scan completion with duration."""
    if not _HAS_PROMETHEUS:
        return
    status = "failed" if failed else "completed"
    SCANS_TOTAL.labels(status=status).inc()
    SCANS_ACTIVE.dec()
    SCAN_DURATION.observe(duration)


def record_finding(severity: str) -> None:
    """Record a single finding by severity level."""
    if not _HAS_PROMETHEUS:
        return
    FINDINGS_TOTAL.labels(severity=severity.lower()).inc()


def record_agent_duration(agent: str, duration: float) -> None:
    """Record agent execution duration."""
    if not _HAS_PROMETHEUS:
        return
    AGENT_DURATION.labels(agent=agent).observe(duration)


def record_api_request(
    method: str, endpoint: str, status: int, duration: float
) -> None:
    """Record an API request."""
    if not _HAS_PROMETHEUS:
        return
    API_REQUESTS_TOTAL.labels(
        method=method, endpoint=endpoint, status=str(status)
    ).inc()
    API_REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)


@contextmanager
def track_scan() -> Generator[None, None, None]:
    """Context manager that tracks scan start/complete with duration."""
    record_scan_start()
    start = time.monotonic()
    failed = False
    try:
        yield
    except Exception:
        failed = True
        raise
    finally:
        record_scan_complete(time.monotonic() - start, failed=failed)


def get_metrics_text() -> tuple[str, str]:
    """Return Prometheus metrics as (body, content_type).

    Returns a placeholder message when prometheus_client is not installed.
    """
    if not _HAS_PROMETHEUS:
        return (
            "# prometheus_client not installed. "
            "Install with: pip install aisec[metrics]\n",
            "text/plain; charset=utf-8",
        )
    body = generate_latest().decode("utf-8")
    return body, CONTENT_TYPE_LATEST


def is_available() -> bool:
    """Return True if prometheus_client is installed."""
    return _HAS_PROMETHEUS
