"""DRF view functions for the AiSec REST API."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from aisec.api.scan_runner import (
    _get_executor,
    _get_history,
    _run_scan_in_thread,
    _scan_futures,
    _start_time,
)
from aisec.api.serializers import _get_serializers

logger = logging.getLogger(__name__)


def _paginate(items: list, page: int = 1, page_size: int = 20, total: int | None = None) -> dict[str, Any]:
    """Wrap a list of items in a pagination envelope."""
    if total is None:
        total = len(items)
    has_more = (page * page_size) < total
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": has_more,
        "results": items,
    }


def _get_actor(request: Any) -> str | None:
    """Extract actor identifier from the request."""
    if hasattr(request, "auth") and request.auth:
        return "api_key"
    return request.META.get("REMOTE_ADDR")


def _get_ip(request: Any) -> str | None:
    """Extract client IP from the request."""
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _get_request_id(request: Any) -> str | None:
    """Extract request ID from headers."""
    return request.META.get("HTTP_X_REQUEST_ID")


def _audit_log(action: str, resource_type: str, resource_id: str | None,
               request: Any, details: str | None = None) -> None:
    """Log an audit event, swallowing errors."""
    try:
        from aisec.core.audit import AuditLogger
        audit = AuditLogger()
        audit.log_event(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor=_get_actor(request),
            details=details,
            request_id=_get_request_id(request),
            ip_address=_get_ip(request),
        )
        audit.close()
    except Exception:
        logger.debug("Audit log failed for %s", action, exc_info=True)


def _get_views() -> dict[str, Any]:
    """Lazily import and return DRF view functions."""
    from rest_framework import status
    from rest_framework.decorators import api_view
    from rest_framework.response import Response

    serializers = _get_serializers()
    ScanRequestSerializer = serializers["ScanRequestSerializer"]
    ScanStatusSerializer = serializers["ScanStatusSerializer"]
    ScanResultSerializer = serializers["ScanResultSerializer"]
    HealthSerializer = serializers["HealthSerializer"]
    AuditEventSerializer = serializers["AuditEventSerializer"]

    @api_view(["GET"])
    def health_check(request: Any) -> Response:
        """Check API server health and version."""
        import aisec
        from aisec.agents.registry import default_registry, register_core_agents
        register_core_agents()
        uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
        data = {
            "status": "healthy",
            "version": aisec.__version__,
            "agents": len(default_registry.get_all()),
            "uptime_seconds": round(uptime, 1),
        }
        serializer = HealthSerializer(data)
        return Response(serializer.data)

    @api_view(["POST"])
    def create_scan(request: Any) -> Response:
        """Submit a new security scan."""
        serializer = ScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated = serializer.validated_data
        scan_id = str(uuid.uuid4())

        from aisec.core.exceptions import error_response
        executor = _get_executor()
        active = sum(1 for f in _scan_futures.values() if not f.done())
        try:
            from aisec.core.config import AiSecConfig
            queue_size = AiSecConfig().scan_queue_size
        except Exception:
            queue_size = 16
        if active >= queue_size:
            return Response(
                error_response("QUEUE_FULL", f"Scan queue full ({active}/{queue_size}). Try again later."),
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        _get_history().save_scan_report(
            scan_id, target_image=validated["image"], image=validated["image"]
        )

        future = executor.submit(
            _run_scan_in_thread,
            scan_id,
            validated["image"],
            validated.get("agents", ["all"]),
            validated.get("skip_agents", []),
            validated.get("formats", ["json"]),
            validated.get("language", "en"),
        )
        _scan_futures[scan_id] = future

        _audit_log("scan.created", "scan", scan_id, request,
                   f"image={validated['image']}")

        result = ScanStatusSerializer({
            "scan_id": scan_id,
            "status": "pending",
            "image": validated["image"],
        })
        return Response(result.data, status=status.HTTP_201_CREATED)

    @api_view(["GET"])
    def get_scan(request: Any, scan_id: str) -> Response:
        """Retrieve scan status and results."""
        from aisec.core.exceptions import error_response
        entry = _get_history().get_scan_report(scan_id)
        if entry is None:
            return Response(
                error_response("SCAN_NOT_FOUND", f"Scan {scan_id} not found"),
                status=status.HTTP_404_NOT_FOUND,
            )
        data = {
            "scan_id": entry["scan_id"],
            "status": entry["status"],
            "image": entry.get("image", entry.get("target_image", "")),
            "started_at": entry.get("created_at"),
            "completed_at": entry.get("completed_at"),
            "report": entry.get("report") if entry["status"] == "completed" else None,
            "error": entry.get("error_message"),
        }
        serializer = ScanResultSerializer(data)
        return Response(serializer.data)

    @api_view(["GET"])
    def list_scans(request: Any) -> Response:
        """List all scans and their statuses (paginated)."""
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        offset = (page - 1) * page_size

        entries = _get_history().list_scan_reports(limit=page_size, offset=offset)
        total = _get_history().count_scan_reports()
        scans = [
            {
                "scan_id": e["scan_id"],
                "status": e["status"],
                "image": e.get("image", e.get("target_image", "")),
                "started_at": e.get("created_at"),
                "completed_at": e.get("completed_at"),
                "finding_count": e.get("finding_count", 0),
                "error": e.get("error_message"),
            }
            for e in entries
        ]
        serializer = ScanStatusSerializer(scans, many=True)
        return Response(_paginate(serializer.data, page, page_size, total))

    @api_view(["DELETE"])
    def delete_scan(request: Any, scan_id: str) -> Response:
        """Delete a completed or failed scan from the store."""
        from aisec.core.exceptions import error_response
        entry = _get_history().get_scan_report(scan_id)
        if entry is None:
            return Response(
                error_response("SCAN_NOT_FOUND", f"Scan {scan_id} not found"),
                status=status.HTTP_404_NOT_FOUND,
            )
        if entry["status"] == "running":
            return Response(
                error_response("SCAN_RUNNING", "Cannot delete a running scan"),
                status=status.HTTP_409_CONFLICT,
            )
        _get_history().delete_scan_report(scan_id)
        _audit_log("scan.deleted", "scan", scan_id, request)
        return Response(
            {"detail": f"Scan {scan_id} deleted"},
            status=status.HTTP_200_OK,
        )

    @api_view(["POST"])
    def cancel_scan(request: Any, scan_id: str) -> Response:
        """Cancel a running or pending scan."""
        from aisec.core.exceptions import error_response
        entry = _get_history().get_scan_report(scan_id)
        if entry is None:
            return Response(
                error_response("SCAN_NOT_FOUND", f"Scan {scan_id} not found"),
                status=status.HTTP_404_NOT_FOUND,
            )
        if entry["status"] not in ("pending", "running"):
            return Response(
                error_response("SCAN_NOT_CANCELLABLE", f"Scan is {entry['status']}"),
                status=status.HTTP_409_CONFLICT,
            )
        future = _scan_futures.get(scan_id)
        if future and not future.done():
            future.cancel()
        _get_history().update_scan_report(scan_id, status="cancelled")
        _audit_log("scan.cancelled", "scan", scan_id, request)
        return Response({"detail": f"Scan {scan_id} cancelled"})

    # -- Webhook management views -------------------------------------------

    WebhookSerializer = serializers["WebhookSerializer"]
    WebhookResponseSerializer = serializers["WebhookResponseSerializer"]
    BatchScanRequestSerializer = serializers["BatchScanRequestSerializer"]

    @api_view(["GET", "POST"])
    def webhooks(request: Any) -> Response:
        """Register or list webhook endpoints."""
        from aisec.core.exceptions import error_response

        if request.method == "POST":
            serializer = WebhookSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            validated = serializer.validated_data

            try:
                from aisec.utils.url_validator import validate_webhook_url
                validate_webhook_url(validated["url"])
            except Exception as exc:
                return Response(
                    error_response("VALIDATION_ERROR", str(exc)),
                    status=status.HTTP_400_BAD_REQUEST,
                )

            wh_id = str(uuid.uuid4())[:8]
            events = validated.get("events", ["scan.completed", "scan.failed"])
            _get_history().save_webhook(
                wh_id, validated["url"], validated.get("secret", ""), events
            )
            _audit_log("webhook.created", "webhook", wh_id, request,
                       f"url={validated['url']}")
            result = WebhookResponseSerializer({
                "webhook_id": wh_id,
                "url": validated["url"],
                "events": events,
            })
            return Response(result.data, status=status.HTTP_201_CREATED)

        # GET (paginated)
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        wh_list = _get_history().list_webhooks()
        items = [
            {"webhook_id": wh["webhook_id"], "url": wh["url"], "events": wh["events"]}
            for wh in wh_list
        ]
        total = len(items)
        start = (page - 1) * page_size
        paged_items = items[start:start + page_size]
        result = WebhookResponseSerializer(paged_items, many=True)
        return Response(_paginate(result.data, page, page_size, total))

    @api_view(["DELETE"])
    def delete_webhook(request: Any, webhook_id: str) -> Response:
        """Remove a registered webhook."""
        from aisec.core.exceptions import error_response
        if not _get_history().delete_webhook(webhook_id):
            return Response(
                error_response("WEBHOOK_NOT_FOUND", f"Webhook {webhook_id} not found"),
                status=status.HTTP_404_NOT_FOUND,
            )
        _audit_log("webhook.deleted", "webhook", webhook_id, request)
        return Response({"detail": f"Webhook {webhook_id} deleted"})

    # -- Batch scanning view -----------------------------------------------

    @api_view(["POST"])
    def batch_scan(request: Any) -> Response:
        """Submit multiple images for scanning in parallel."""
        serializer = BatchScanRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated = serializer.validated_data
        images = validated["images"]
        if not images:
            from aisec.core.exceptions import error_response
            return Response(
                error_response("VALIDATION_ERROR", "At least one image is required"),
                status=status.HTTP_400_BAD_REQUEST,
            )

        executor = _get_executor()
        scan_ids = []
        for image in images:
            scan_id = str(uuid.uuid4())
            _get_history().save_scan_report(
                scan_id, target_image=image, image=image
            )
            future = executor.submit(
                _run_scan_in_thread,
                scan_id,
                image,
                validated.get("agents", ["all"]),
                validated.get("skip_agents", []),
                validated.get("formats", ["json"]),
                validated.get("language", "en"),
            )
            _scan_futures[scan_id] = future
            scan_ids.append({"scan_id": scan_id, "image": image})

        return Response(
            {"batch_size": len(images), "scans": scan_ids},
            status=status.HTTP_201_CREATED,
        )

    # -- Prometheus metrics endpoint ------------------------------------------

    @api_view(["GET"])
    def metrics_view(request: Any) -> Response:
        """Expose Prometheus-format metrics at /api/metrics/."""
        from django.http import HttpResponse
        from aisec.core.metrics import get_metrics_text

        body, content_type = get_metrics_text()
        return HttpResponse(body, content_type=content_type)

    # -- Scan schedule management views ----------------------------------------

    @api_view(["GET", "POST"])
    def schedules(request: Any) -> Response:
        """Manage scheduled scans."""
        from aisec.api.scan_runner import _scheduler_instance as _sched
        import aisec.api.scan_runner as sr

        if request.method == "POST":
            from aisec.core.exceptions import error_response
            data = request.data
            image = data.get("image")
            cron = data.get("cron")
            if not image or not cron:
                return Response(
                    error_response("VALIDATION_ERROR", "Both 'image' and 'cron' fields are required"),
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if sr._scheduler_instance is None:
                try:
                    from aisec.core.scheduler import ScanScheduler

                    def _scheduled_scan_callback(image: str, agents: list[str], language: str) -> None:
                        scan_id = str(uuid.uuid4())
                        _get_history().save_scan_report(
                            scan_id, target_image=image, image=image
                        )
                        executor = _get_executor()
                        future = executor.submit(
                            _run_scan_in_thread,
                            scan_id, image, agents, [], ["json"], language,
                        )
                        _scan_futures[scan_id] = future

                    sr._scheduler_instance = ScanScheduler(scan_callback=_scheduled_scan_callback)
                    sr._scheduler_instance.start()
                except Exception as exc:
                    return Response(
                        {"detail": f"Scheduler unavailable: {exc}"},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )

            agents = data.get("agents", ["all"])
            language = data.get("language", "en")

            try:
                entry = sr._scheduler_instance.add_schedule(
                    image=image, cron=cron, agents=agents, language=language
                )
            except Exception as exc:
                return Response(
                    {"detail": f"Invalid cron expression: {exc}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(entry.to_dict(), status=status.HTTP_201_CREATED)

        # GET
        if sr._scheduler_instance is None:
            return Response([])
        return Response(sr._scheduler_instance.list_schedules())

    @api_view(["DELETE"])
    def delete_schedule(request: Any, schedule_id: str) -> Response:
        """Remove a scheduled scan."""
        import aisec.api.scan_runner as sr
        if sr._scheduler_instance is None or not sr._scheduler_instance.remove_schedule(schedule_id):
            return Response(
                {"detail": f"Schedule {schedule_id} not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({"detail": f"Schedule {schedule_id} deleted"})

    # -- Audit log endpoint ---------------------------------------------------

    @api_view(["GET"])
    def audit_events(request: Any) -> Response:
        """List audit events (paginated)."""
        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))
        action = request.query_params.get("action")
        resource_type = request.query_params.get("resource_type")

        try:
            from aisec.core.audit import AuditLogger
            audit = AuditLogger()
            events = audit.list_events(
                action=action,
                resource_type=resource_type,
                limit=page_size,
                offset=(page - 1) * page_size,
            )
            total = audit.count_events(action=action, resource_type=resource_type)
            audit.close()
        except Exception:
            events = []
            total = 0

        serializer = AuditEventSerializer(events, many=True)
        return Response(_paginate(serializer.data, page, page_size, total))

    return {
        "health_check": health_check,
        "create_scan": create_scan,
        "get_scan": get_scan,
        "list_scans": list_scans,
        "delete_scan": delete_scan,
        "cancel_scan": cancel_scan,
        "webhooks": webhooks,
        "delete_webhook": delete_webhook,
        "batch_scan": batch_scan,
        "metrics_view": metrics_view,
        "schedules": schedules,
        "delete_schedule": delete_schedule,
        "audit_events": audit_events,
    }
