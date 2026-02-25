"""Shared context processors for dashboard templates."""

from __future__ import annotations

from typing import Any

import aisec


def dashboard_context(request: Any) -> dict[str, Any]:
    """Inject shared context into every dashboard template."""
    try:
        from aisec.cli.serve import _get_history
        reports = _get_history().list_scan_reports()
        active_scans = sum(
            1 for s in reports if s.get("status") in ("pending", "running")
        )
    except Exception:
        active_scans = 0

    nav_items = [
        {"url": "/dashboard/", "label": "Home", "icon": "home"},
        {"url": "/dashboard/scans/", "label": "Scans", "icon": "search"},
        {"url": "/dashboard/findings/", "label": "Findings", "icon": "alert-triangle"},
        {"url": "/dashboard/trends/", "label": "Trends", "icon": "trending-up"},
        {"url": "/dashboard/policies/", "label": "Policies", "icon": "shield"},
        {"url": "/dashboard/new-scan/", "label": "New Scan", "icon": "plus-circle"},
    ]

    return {
        "aisec_version": aisec.__version__,
        "nav_items": nav_items,
        "active_scan_count": active_scans,
    }
