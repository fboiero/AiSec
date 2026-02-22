"""Tests for InterServiceSecurityAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.inter_service import (
    GRPC_REFLECTION_PATTERN,
    HMAC_PATTERNS,
    HTTP_INTERNAL_PATTERNS,
    MQ_PATTERNS,
    WEBHOOK_PATTERNS,
    InterServiceSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestInterServiceMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert InterServiceSecurityAgent.name == "inter_service"

    def test_phase(self):
        assert InterServiceSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM07" in InterServiceSecurityAgent.frameworks
        assert "ASI03" in InterServiceSecurityAgent.frameworks

    def test_depends_on(self):
        assert "network" in InterServiceSecurityAgent.depends_on
        assert "api_security" in InterServiceSecurityAgent.depends_on


class TestWebhookPatterns:
    """Test webhook detection patterns."""

    def test_webhook_patterns_defined(self):
        assert len(WEBHOOK_PATTERNS) >= 3

    def test_flask_webhook_matches(self):
        _, pattern = WEBHOOK_PATTERNS[0]
        assert pattern.search('@app.route("/webhook")')
        assert pattern.search('@app.post("/api/webhook")')

    def test_hmac_pattern_matches(self):
        assert HMAC_PATTERNS.search("hmac.compare_digest(sig, expected)")
        assert HMAC_PATTERNS.search("verify_signature(payload, secret)")


class TestMessageQueuePatterns:
    """Test message queue patterns."""

    def test_mq_patterns_defined(self):
        assert len(MQ_PATTERNS) >= 3

    def test_redis_without_password(self):
        _, pattern, _ = MQ_PATTERNS[2]
        assert pattern.search('Redis(host="localhost", port=6379)')


class TestHTTPPatterns:
    """Test internal HTTP patterns."""

    def test_internal_http_matches(self):
        assert HTTP_INTERNAL_PATTERNS.search("http://localhost:8080")
        assert HTTP_INTERNAL_PATTERNS.search("http://127.0.0.1:5000")
        assert HTTP_INTERNAL_PATTERNS.search("http://10.0.0.1/api")

    def test_https_not_matched(self):
        assert not HTTP_INTERNAL_PATTERNS.search("https://example.com")


class TestGRPCPatterns:
    """Test gRPC reflection patterns."""

    def test_grpc_reflection_matches(self):
        assert GRPC_REFLECTION_PATTERN.search("grpc_reflection.enable()")
        assert GRPC_REFLECTION_PATTERN.search("reflection.enable(server)")


class TestInterServiceNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = InterServiceSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestWebhookSecurity:
    """Test webhook security checking."""

    def test_detects_webhook_without_hmac(self, scan_context):
        agent = InterServiceSecurityAgent(scan_context)
        files = {
            "/app/webhooks.py": (
                '@app.post("/webhook")\n'
                'def handle_webhook(request):\n'
                '    data = request.json\n'
                '    process(data)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_webhook_security(files, combined)
        webhook_findings = [f for f in agent.findings if "webhook" in f.title.lower()]
        assert len(webhook_findings) >= 1

    def test_webhook_with_hmac_ok(self, scan_context):
        agent = InterServiceSecurityAgent(scan_context)
        files = {
            "/app/webhooks.py": (
                '@app.post("/webhook")\n'
                'def handle_webhook(request):\n'
                '    sig = request.headers["X-Hub-Signature"]\n'
                '    if not hmac.compare_digest(sig, expected):\n'
                '        abort(403)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_webhook_security(files, combined)
        webhook_findings = [f for f in agent.findings if "webhook" in f.title.lower()]
        assert len(webhook_findings) == 0


class TestMTLSDetection:
    """Test mTLS absence detection."""

    def test_detects_internal_http(self, scan_context):
        agent = InterServiceSecurityAgent(scan_context)
        files = {
            "/app/client.py": (
                'response = requests.get("http://localhost:8080/api/data")\n'
                'data = requests.post("http://10.0.0.5/process", json=payload)\n'
            )
        }
        agent._check_mtls_absence(files)
        tls_findings = [f for f in agent.findings if "TLS" in f.title]
        assert len(tls_findings) >= 1


class TestGRPCReflection:
    """Test gRPC reflection detection."""

    def test_detects_grpc_reflection(self, scan_context):
        agent = InterServiceSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from grpc_reflection.v1alpha import reflection\n'
                'reflection.enable(server)\n'
            )
        }
        agent._check_grpc_reflection(files)
        grpc_findings = [f for f in agent.findings if "gRPC" in f.title]
        assert len(grpc_findings) >= 1
