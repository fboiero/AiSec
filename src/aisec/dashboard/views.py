"""Dashboard view functions for the AiSec web UI."""

from __future__ import annotations

import json
import logging
import math
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.template import loader

logger = logging.getLogger(__name__)

# Page size for paginated views
PAGE_SIZE = 20


def _get_history():
    """Get a ScanHistory instance."""
    from aisec.core.history import ScanHistory
    return ScanHistory()


def _render(request: HttpRequest, template: str, context: dict[str, Any]) -> HttpResponse:
    """Render a dashboard template with context."""
    t = loader.get_template(template)
    return HttpResponse(t.render(context, request))


# ---------------------------------------------------------------------------
# Page views
# ---------------------------------------------------------------------------


def home(request: HttpRequest) -> HttpResponse:
    """Dashboard home page — summary cards, severity donut, recent scans."""
    history = _get_history()
    try:
        stats = history.stats()
        recent_scans = history.list_scans(limit=10)
        severity_dist = history.severity_distribution()
        trend_data = history.global_trend(limit=14)

        # Active scans from in-memory store
        from aisec.cli.serve import _scan_store
        active_scans = [
            s for s in _scan_store.values()
            if s.get("status") in ("pending", "running")
        ]

        context = {
            "stats": stats,
            "recent_scans": recent_scans,
            "severity_dist": json.dumps(severity_dist),
            "trend_data": json.dumps(list(reversed(trend_data))),
            "active_scans": active_scans,
            "page_title": "Dashboard",
        }
        return _render(request, "dashboard/home.html", context)
    finally:
        history.close()


def scan_list(request: HttpRequest) -> HttpResponse:
    """Paginated/filterable scan list."""
    history = _get_history()
    try:
        target = request.GET.get("target")
        page = int(request.GET.get("page", "1"))
        offset = (page - 1) * PAGE_SIZE

        scans = history.list_scans(target_image=target, limit=PAGE_SIZE, offset=offset)
        total = history.count_scans(target_image=target)
        total_pages = max(1, math.ceil(total / PAGE_SIZE))
        targets = history.distinct_targets()

        context = {
            "scans": scans,
            "targets": targets,
            "selected_target": target or "",
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "page_title": "Scans",
        }
        return _render(request, "dashboard/scans.html", context)
    finally:
        history.close()


def scan_detail(request: HttpRequest, scan_id: str) -> HttpResponse:
    """Detailed scan view with tabs."""
    history = _get_history()
    try:
        scan = history.get_scan(scan_id)
        if not scan:
            # Check in-memory store for active scans
            from aisec.cli.serve import _scan_store
            active = _scan_store.get(scan_id)
            if active:
                context = {
                    "scan": active,
                    "findings": [],
                    "is_active": True,
                    "page_title": f"Scan {scan_id[:8]}",
                }
                return _render(request, "dashboard/scan_detail.html", context)
            return HttpResponse("Scan not found", status=404)

        findings = history.get_findings(scan_id)
        trend = history.get_trend(scan["target_image"], limit=10)

        # Group findings by agent
        by_agent: dict[str, list] = {}
        for f in findings:
            agent = f.get("agent", "unknown")
            by_agent.setdefault(agent, []).append(f)

        # Parse metadata
        metadata = {}
        if scan.get("metadata"):
            try:
                metadata = json.loads(scan["metadata"])
            except (json.JSONDecodeError, TypeError):
                pass

        context = {
            "scan": scan,
            "findings": findings,
            "findings_by_agent": by_agent,
            "trend": json.dumps(trend),
            "metadata": metadata,
            "is_active": False,
            "page_title": f"Scan {scan_id[:8]}",
        }
        return _render(request, "dashboard/scan_detail.html", context)
    finally:
        history.close()


def findings_explorer(request: HttpRequest) -> HttpResponse:
    """Global findings explorer with filters."""
    history = _get_history()
    try:
        severity = request.GET.get("severity")
        agent = request.GET.get("agent")
        framework = request.GET.get("framework")
        status_filter = request.GET.get("status")
        page = int(request.GET.get("page", "1"))
        offset = (page - 1) * PAGE_SIZE

        findings = history.search_findings(
            severity=severity,
            agent=agent,
            framework=framework,
            status=status_filter,
            limit=PAGE_SIZE,
            offset=offset,
        )

        severity_dist = history.severity_distribution()

        context = {
            "findings": findings,
            "severity_dist": severity_dist,
            "selected_severity": severity or "",
            "selected_agent": agent or "",
            "selected_framework": framework or "",
            "selected_status": status_filter or "",
            "page": page,
            "page_title": "Findings Explorer",
        }
        return _render(request, "dashboard/findings.html", context)
    finally:
        history.close()


def trends(request: HttpRequest) -> HttpResponse:
    """Time-series trend charts."""
    history = _get_history()
    try:
        trend_data = history.global_trend(limit=60)
        targets = history.distinct_targets()

        # Per-target trends
        target_trends = {}
        for t in targets[:5]:  # Limit to top 5 targets
            target_trends[t] = history.get_trend(t, limit=20)

        context = {
            "trend_data": json.dumps(list(reversed(trend_data))),
            "targets": targets,
            "target_trends": json.dumps(
                {k: list(reversed(v)) for k, v in target_trends.items()}
            ),
            "page_title": "Trends",
        }
        return _render(request, "dashboard/trends.html", context)
    finally:
        history.close()


def policies(request: HttpRequest) -> HttpResponse:
    """Policy cards and saved policies."""
    history = _get_history()
    try:
        saved_policies = history.list_policies()

        # Load built-in policy descriptions
        builtin_policies = []
        for name in ("strict", "moderate", "permissive"):
            try:
                from aisec.policies.loader import load_policy
                policy = load_policy(name)
                builtin_policies.append({
                    "name": name,
                    "description": policy.description,
                    "gate_block_count": len(policy.gate.block_on),
                    "gate_warn_count": len(policy.gate.warn_on),
                    "required_agents": policy.required_agents,
                    "max_critical": policy.thresholds.max_critical,
                    "max_high": policy.thresholds.max_high,
                })
            except Exception:
                builtin_policies.append({"name": name, "description": f"Built-in {name} policy"})

        context = {
            "builtin_policies": builtin_policies,
            "saved_policies": saved_policies,
            "page_title": "Policies",
        }
        return _render(request, "dashboard/policies.html", context)
    finally:
        history.close()


def new_scan(request: HttpRequest) -> HttpResponse:
    """Scan submission form and handler."""
    from aisec.cli.serve import _run_scan_in_thread, _scan_store

    if request.method == "POST":
        image = request.POST.get("image", "").strip()
        if not image:
            context = {"error": "Docker image is required", "page_title": "New Scan"}
            return _render(request, "dashboard/new_scan.html", context)

        agents_raw = request.POST.get("agents", "all").strip()
        agents = [a.strip() for a in agents_raw.split(",") if a.strip()] or ["all"]
        language = request.POST.get("language", "en")
        formats = ["json", "html"]

        scan_id = str(uuid.uuid4())
        _scan_store[scan_id] = {
            "scan_id": scan_id,
            "status": "pending",
            "image": image,
            "started_at": None,
            "completed_at": None,
            "finding_count": 0,
            "report": None,
            "error": None,
        }

        t = threading.Thread(
            target=_run_scan_in_thread,
            args=(scan_id, image, agents, [], formats, language),
            daemon=True,
        )
        t.start()

        from django.http import HttpResponseRedirect
        return HttpResponseRedirect(f"/dashboard/scans/{scan_id}/")

    # GET — render form
    from aisec.agents.registry import default_registry, register_core_agents
    register_core_agents()
    agent_names = sorted(default_registry.get_all().keys())

    history = _get_history()
    try:
        targets = history.distinct_targets()
    finally:
        history.close()

    context = {
        "agent_names": agent_names,
        "targets": targets,
        "page_title": "New Scan",
    }
    return _render(request, "dashboard/new_scan.html", context)


# ---------------------------------------------------------------------------
# HTMX partial views
# ---------------------------------------------------------------------------


def partial_scan_table(request: HttpRequest) -> HttpResponse:
    """HTMX partial: scan table rows."""
    history = _get_history()
    try:
        target = request.GET.get("target")
        page = int(request.GET.get("page", "1"))
        offset = (page - 1) * PAGE_SIZE

        scans = history.list_scans(target_image=target, limit=PAGE_SIZE, offset=offset)
        total = history.count_scans(target_image=target)
        total_pages = max(1, math.ceil(total / PAGE_SIZE))

        context = {
            "scans": scans,
            "page": page,
            "total_pages": total_pages,
        }
        return _render(request, "dashboard/partials/scan_table.html", context)
    finally:
        history.close()


def partial_scan_status(request: HttpRequest, scan_id: str) -> HttpResponse:
    """HTMX partial: scan status badge with auto-poll."""
    from aisec.cli.serve import _scan_store
    entry = _scan_store.get(scan_id)

    if not entry:
        history = _get_history()
        try:
            scan = history.get_scan(scan_id)
            status = scan["status"] if scan else "unknown"
            # Completed scans don't exist in _scan_store
            if scan:
                status = "completed"
        finally:
            history.close()
    else:
        status = entry.get("status", "unknown")

    context = {"scan_id": scan_id, "status": status}
    response = _render(request, "dashboard/partials/scan_status.html", context)

    # Stop polling when scan is done
    if status in ("completed", "failed"):
        response["HX-Trigger"] = "scanComplete"

    return response


def partial_finding_rows(request: HttpRequest) -> HttpResponse:
    """HTMX partial: finding table rows."""
    history = _get_history()
    try:
        severity = request.GET.get("severity")
        agent = request.GET.get("agent")
        framework = request.GET.get("framework")
        status_filter = request.GET.get("status")
        page = int(request.GET.get("page", "1"))
        offset = (page - 1) * PAGE_SIZE

        findings = history.search_findings(
            severity=severity,
            agent=agent,
            framework=framework,
            status=status_filter,
            limit=PAGE_SIZE,
            offset=offset,
        )

        context = {"findings": findings, "page": page}
        return _render(request, "dashboard/partials/finding_rows.html", context)
    finally:
        history.close()
