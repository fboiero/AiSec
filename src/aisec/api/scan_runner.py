"""Background scan execution and webhook dispatch.

Manages the ThreadPoolExecutor for async scan execution and
provides webhook notification dispatch.
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import hmac
import json
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from enum import Enum

from aisec.core.metrics import (
    record_finding,
    record_scan_start,
    record_scan_complete,
)

logger = logging.getLogger(__name__)

_start_time = datetime.now(timezone.utc)
_history: Any = None  # ScanHistory singleton
_executor: ThreadPoolExecutor | None = None
_scan_futures: dict[str, Future] = {}  # scan_id -> Future for cancellation

# Scheduler singleton (initialised in serve() when --schedule is provided)
_scheduler_instance: Any = None


class _ReportEncoder(json.JSONEncoder):
    """JSON encoder that handles UUIDs, datetimes, and enums."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def _get_history() -> Any:
    """Get or create the ScanHistory singleton."""
    global _history
    if _history is None:
        from aisec.core.history import ScanHistory
        _history = ScanHistory()
    return _history


def _get_executor() -> ThreadPoolExecutor:
    """Get or create the ThreadPoolExecutor singleton."""
    global _executor
    if _executor is None:
        try:
            from aisec.core.config import AiSecConfig
            cfg = AiSecConfig()
            max_workers = cfg.max_concurrent_scans
        except Exception:
            max_workers = 4
        _executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="aisec-scan",
        )
    return _executor


def _graceful_shutdown(*_args: Any) -> None:
    """Shut down executor and close history DB on exit."""
    global _executor, _history
    if _executor:
        _executor.shutdown(wait=False, cancel_futures=True)
        _executor = None
    if _history:
        _history.close()
        _history = None


atexit.register(_graceful_shutdown)


def _dispatch_webhooks(event: str, payload: dict[str, Any]) -> None:
    """Send event notifications to all registered webhooks."""
    from urllib.request import Request, urlopen

    try:
        webhooks = _get_history().list_webhooks(active_only=True)
    except Exception:
        webhooks = []

    for wh in webhooks:
        events = wh.get("events", ["scan.completed", "scan.failed"])
        if event not in events:
            continue

        url = wh["url"]
        body = json.dumps({"event": event, "payload": payload}).encode()

        headers = {"Content-Type": "application/json", "X-AiSec-Event": event}

        secret = wh.get("secret")
        if secret:
            sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-AiSec-Signature"] = f"sha256={sig}"

        try:
            from aisec.core.config import AiSecConfig
            timeout = AiSecConfig().webhook_timeout
        except Exception:
            timeout = 10

        try:
            req = Request(url, data=body, headers=headers, method="POST")
            urlopen(req, timeout=timeout)  # noqa: S310
            logger.info("Webhook %s dispatched to %s", event, url)
        except Exception as exc:
            logger.warning("Webhook %s to %s failed: %s", event, url, exc)


def _run_scan_in_thread(scan_id: str, image: str, agents: list[str],
                        skip_agents: list[str], formats: list[str],
                        language: str) -> None:
    """Execute a scan in a background thread and store results."""
    from aisec.core.config import AiSecConfig
    from aisec.core.context import ScanContext
    from aisec.agents.orchestrator import Orchestrator
    from aisec.agents.registry import default_registry, register_core_agents
    from aisec.docker_.manager import DockerManager
    from aisec.reports.builder import ReportBuilder

    _get_history().update_scan_report(scan_id, status="running")
    record_scan_start()
    _scan_start = time.monotonic()

    try:
        config = AiSecConfig(
            agents=agents,
            skip_agents=skip_agents,
            output_formats=formats,
            language=language,
        )

        ctx = ScanContext(target_image=image, config=config)
        register_core_agents()

        dm = DockerManager(image=image)
        dm.start()
        ctx.docker_manager = dm
        ctx.container_id = dm.container_id

        try:
            orch = Orchestrator(ctx, default_registry)
            asyncio.run(orch.run_all())
        finally:
            dm.stop()

        builder = ReportBuilder(ctx)
        report = builder.build()

        report_dict = asdict(report)

        finding_count = report.executive_summary.total_findings
        _get_history().update_scan_report(
            scan_id,
            status="completed",
            report_json=json.dumps(report_dict, cls=_ReportEncoder),
            finding_count=finding_count,
        )

        record_scan_complete(time.monotonic() - _scan_start)

        # Record per-finding metrics
        for section in getattr(report, "agent_reports", []):
            for finding in getattr(section, "findings", []):
                sev = getattr(finding, "severity", None)
                if sev:
                    record_finding(str(sev.value) if hasattr(sev, "value") else str(sev))

        # Persist to SQLite history
        try:
            from aisec.core.history import ScanHistory
            history = ScanHistory()
            history.save_scan(report)
            history.close()
        except Exception as hist_exc:
            logger.warning("Failed to save scan to history: %s", hist_exc)

        _dispatch_webhooks("scan.completed", {
            "scan_id": scan_id,
            "image": image,
            "finding_count": finding_count,
            "critical_count": report.executive_summary.critical_count,
            "high_count": report.executive_summary.high_count,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        _get_history().update_scan_report(
            scan_id, status="failed", error_message=str(exc)
        )
        record_scan_complete(time.monotonic() - _scan_start, failed=True)

        _dispatch_webhooks("scan.failed", {
            "scan_id": scan_id,
            "image": image,
            "error": str(exc),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
