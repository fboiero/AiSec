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

    class ModelRiskEvaluationRequestSerializer(serializers.Serializer):
        schema_version = serializers.CharField(required=False)
        request_id = serializers.CharField(required=False)
        source = serializers.CharField(required=False)
        target = serializers.DictField()
        frameworks = serializers.ListField(child=serializers.CharField(), required=False)
        context = serializers.DictField(required=False)
        policy = serializers.DictField(required=False)

    class ModelRiskEvaluationStatusSerializer(serializers.Serializer):
        evaluation_id = serializers.CharField()
        request_id = serializers.CharField()
        target_name = serializers.CharField()
        target_type = serializers.CharField()
        provider = serializers.CharField(allow_blank=True, default="")
        model_id = serializers.CharField(allow_blank=True, default="")
        source = serializers.CharField(allow_blank=True, default="")
        overall_risk = serializers.CharField()
        risk_score = serializers.FloatField()
        policy_verdict = serializers.CharField()
        finding_count = serializers.IntegerField()
        created_at = serializers.CharField()

    class ModelRiskEvaluationRecordSerializer(serializers.Serializer):
        evaluation_id = serializers.CharField()
        request_id = serializers.CharField()
        target_name = serializers.CharField()
        target_type = serializers.CharField()
        provider = serializers.CharField(allow_blank=True, default="")
        model_id = serializers.CharField(allow_blank=True, default="")
        source = serializers.CharField(allow_blank=True, default="")
        overall_risk = serializers.CharField()
        risk_score = serializers.FloatField()
        policy_verdict = serializers.CharField()
        finding_count = serializers.IntegerField()
        created_at = serializers.CharField()
        request = serializers.DictField()
        result = serializers.DictField()

    class ModelRiskEvaluationRollupSerializer(serializers.Serializer):
        total_evaluations = serializers.IntegerField()
        unique_targets = serializers.IntegerField()
        average_risk_score = serializers.FloatField()
        risk_counts = serializers.DictField()
        policy_counts = serializers.DictField()
        latest = serializers.ListField(child=serializers.DictField())

    class ModelRiskEvaluationTrendsSerializer(serializers.Serializer):
        total_evaluations = serializers.IntegerField()
        by_target = serializers.ListField(child=serializers.DictField())
        by_provider = serializers.ListField(child=serializers.DictField())
        by_project = serializers.ListField(child=serializers.DictField())
        by_framework = serializers.ListField(child=serializers.DictField())
        by_day = serializers.ListField(child=serializers.DictField())

    class ModelRiskBaselineRequestSerializer(serializers.Serializer):
        name = serializers.CharField()
        target_name = serializers.CharField()
        evaluation_id = serializers.CharField()
        description = serializers.CharField(required=False, allow_blank=True, default="")

    class ModelRiskBaselineSerializer(serializers.Serializer):
        baseline_id = serializers.CharField()
        name = serializers.CharField()
        target_name = serializers.CharField()
        evaluation_id = serializers.CharField()
        created_at = serializers.CharField()
        description = serializers.CharField(allow_blank=True, default="")

    class ModelRiskBaselineCompareRequestSerializer(serializers.Serializer):
        current_evaluation_id = serializers.CharField()

    class ModelRiskExceptionRequestSerializer(serializers.Serializer):
        target_name = serializers.CharField()
        finding_fingerprint = serializers.CharField()
        reason = serializers.CharField()
        accepted_by = serializers.CharField(required=False, allow_blank=True, default="")
        expires_at = serializers.CharField(required=False, allow_blank=True, allow_null=True, default=None)

    class ModelRiskExceptionSerializer(serializers.Serializer):
        exception_id = serializers.CharField()
        target_name = serializers.CharField()
        finding_fingerprint = serializers.CharField()
        reason = serializers.CharField()
        accepted_by = serializers.CharField(allow_blank=True, default="")
        expires_at = serializers.CharField(allow_null=True, required=False)
        created_at = serializers.CharField()
        active = serializers.IntegerField()

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
        "ModelRiskEvaluationRequestSerializer": ModelRiskEvaluationRequestSerializer,
        "ModelRiskEvaluationStatusSerializer": ModelRiskEvaluationStatusSerializer,
        "ModelRiskEvaluationRecordSerializer": ModelRiskEvaluationRecordSerializer,
        "ModelRiskEvaluationRollupSerializer": ModelRiskEvaluationRollupSerializer,
        "ModelRiskEvaluationTrendsSerializer": ModelRiskEvaluationTrendsSerializer,
        "ModelRiskBaselineRequestSerializer": ModelRiskBaselineRequestSerializer,
        "ModelRiskBaselineSerializer": ModelRiskBaselineSerializer,
        "ModelRiskBaselineCompareRequestSerializer": ModelRiskBaselineCompareRequestSerializer,
        "ModelRiskExceptionRequestSerializer": ModelRiskExceptionRequestSerializer,
        "ModelRiskExceptionSerializer": ModelRiskExceptionSerializer,
        "AuditEventSerializer": AuditEventSerializer,
    }
