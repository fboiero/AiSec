"""DRF serializers for the AiSec REST API."""

from __future__ import annotations

from typing import Any


def _get_serializers() -> dict[str, Any]:
    """Lazily import and return DRF serializer classes."""
    from rest_framework import serializers

    class ScanRequestSerializer(serializers.Serializer):
        image = serializers.CharField(
            help_text="Docker image to scan (e.g. 'myapp:latest')")
        agents = serializers.ListField(
            child=serializers.CharField(), default=["all"],
            help_text="Agents to run")
        skip_agents = serializers.ListField(
            child=serializers.CharField(), default=[],
            help_text="Agents to skip")
        formats = serializers.ListField(
            child=serializers.CharField(), default=["json"],
            help_text="Output formats")
        language = serializers.CharField(
            default="en", help_text="Report language (en/es)")

    class ScanStatusSerializer(serializers.Serializer):
        scan_id = serializers.CharField()
        status = serializers.CharField()
        image = serializers.CharField()
        started_at = serializers.CharField(allow_null=True, default=None)
        completed_at = serializers.CharField(allow_null=True, default=None)
        finding_count = serializers.IntegerField(default=0)
        error = serializers.CharField(allow_null=True, default=None)

    class ScanResultSerializer(serializers.Serializer):
        scan_id = serializers.CharField()
        status = serializers.CharField()
        image = serializers.CharField()
        started_at = serializers.CharField(allow_null=True, default=None)
        completed_at = serializers.CharField(allow_null=True, default=None)
        report = serializers.DictField(allow_null=True, default=None)
        error = serializers.CharField(allow_null=True, default=None)

    class HealthSerializer(serializers.Serializer):
        status = serializers.CharField()
        version = serializers.CharField()
        agents = serializers.IntegerField()
        uptime_seconds = serializers.FloatField()

    class WebhookSerializer(serializers.Serializer):
        url = serializers.URLField(help_text="Webhook endpoint URL")
        secret = serializers.CharField(
            required=False, default="",
            help_text="HMAC-SHA256 secret for payload signing")
        events = serializers.ListField(
            child=serializers.CharField(),
            default=["scan.completed", "scan.failed"],
            help_text="Events to subscribe to")

    class WebhookResponseSerializer(serializers.Serializer):
        webhook_id = serializers.CharField()
        url = serializers.CharField()
        events = serializers.ListField(child=serializers.CharField())

    class BatchScanRequestSerializer(serializers.Serializer):
        images = serializers.ListField(
            child=serializers.CharField(),
            help_text="List of Docker images to scan")
        agents = serializers.ListField(
            child=serializers.CharField(), default=["all"],
            help_text="Agents to run")
        skip_agents = serializers.ListField(
            child=serializers.CharField(), default=[],
            help_text="Agents to skip")
        formats = serializers.ListField(
            child=serializers.CharField(), default=["json"],
            help_text="Output formats")
        language = serializers.CharField(
            default="en", help_text="Report language (en/es)")

    class AuditEventSerializer(serializers.Serializer):
        event_id = serializers.CharField()
        timestamp = serializers.CharField()
        action = serializers.CharField()
        resource_type = serializers.CharField()
        resource_id = serializers.CharField(allow_null=True, default=None)
        actor = serializers.CharField(allow_null=True, default=None)
        details = serializers.CharField(allow_null=True, default=None)
        request_id = serializers.CharField(allow_null=True, default=None)
        ip_address = serializers.CharField(allow_null=True, default=None)

    return {
        "ScanRequestSerializer": ScanRequestSerializer,
        "ScanStatusSerializer": ScanStatusSerializer,
        "ScanResultSerializer": ScanResultSerializer,
        "HealthSerializer": HealthSerializer,
        "WebhookSerializer": WebhookSerializer,
        "WebhookResponseSerializer": WebhookResponseSerializer,
        "BatchScanRequestSerializer": BatchScanRequestSerializer,
        "AuditEventSerializer": AuditEventSerializer,
    }
