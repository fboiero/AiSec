"""Tests for APISecurityAgent."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aisec.agents.api_security import (
    AI_API_PATHS,
    APISecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import AgentResult, Evidence, Finding


class TestAPISecurityAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert APISecurityAgent.name == "api_security"

    def test_phase(self):
        assert APISecurityAgent.phase == AgentPhase.DYNAMIC

    def test_frameworks(self):
        assert "LLM01" in APISecurityAgent.frameworks
        assert "LLM10" in APISecurityAgent.frameworks
        assert "ASI03" in APISecurityAgent.frameworks

    def test_depends_on(self):
        assert "network" in APISecurityAgent.depends_on


class TestConstants:
    """Test agent constants."""

    def test_ai_api_paths_populated(self):
        assert len(AI_API_PATHS) >= 10
        assert "/v1/models" in AI_API_PATHS
        assert "/v1/chat/completions" in AI_API_PATHS
        assert "/health" in AI_API_PATHS
        assert "/metrics" in AI_API_PATHS
        assert "/graphql" in AI_API_PATHS


class TestEndpointDiscovery:
    """Test endpoint discovery."""

    @pytest.mark.asyncio
    async def test_no_endpoints_returns_info(self, scan_context):
        agent = APISecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert "No API endpoints" in agent.findings[0].title

    @pytest.mark.asyncio
    async def test_discover_from_container_ports(self, scan_context):
        scan_context.container_id = "test-container"
        agent = APISecurityAgent(scan_context)

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(
                return_value=(b'{"8080/tcp":{}}', b"")
            )
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            endpoints = await agent._discover_endpoints()

        assert len(endpoints) >= 1
        assert "http://localhost:8080" in endpoints

    @pytest.mark.asyncio
    async def test_discover_from_network_agent(self, scan_context):
        # Set up network agent results with port information
        network_result = AgentResult(
            agent="network",
            findings=[
                Finding(
                    title="Open port detected",
                    description="Port 8000 is open",
                    severity=Severity.INFO,
                    agent="network",
                    evidence=[
                        Evidence(
                            type="network_capture",
                            summary="port scan",
                            raw_data="port 8000 open",
                        )
                    ],
                )
            ],
        )
        scan_context.agent_results["network"] = network_result
        agent = APISecurityAgent(scan_context)

        endpoints = await agent._discover_endpoints()
        assert len(endpoints) >= 1


class TestAuthBypass:
    """Test authentication bypass detection."""

    @pytest.mark.asyncio
    async def test_unauth_endpoints_detected(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(200, {}, '{"data": "models_list"}'),
        ):
            await agent._check_auth_bypass(["http://localhost:8080"])

        auth_findings = [
            f for f in agent.findings if "Unauthenticated" in f.title
        ]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_auth_required_not_flagged(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(401, {}, '{"error": "unauthorized"}'),
        ):
            await agent._check_auth_bypass(["http://localhost:8080"])

        auth_findings = [
            f for f in agent.findings if "Unauthenticated" in f.title
        ]
        assert len(auth_findings) == 0


class TestRateLimiting:
    """Test rate limiting detection."""

    @pytest.mark.asyncio
    async def test_no_rate_limit_detected(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(200, {}, '{"ok": true}'),
        ):
            await agent._check_rate_limiting(["http://localhost:8080"])

        rate_findings = [
            f for f in agent.findings if "rate limit" in f.title.lower()
        ]
        assert len(rate_findings) == 1
        assert rate_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_rate_limit_present(self, scan_context):
        agent = APISecurityAgent(scan_context)

        call_count = 0

        async def mock_http(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count > 10:
                return (429, {"Retry-After": "60"}, "Too many requests")
            return (200, {"X-RateLimit-Remaining": "5"}, '{"ok": true}')

        with patch.object(agent, "_http_request", side_effect=mock_http):
            await agent._check_rate_limiting(["http://localhost:8080"])

        rate_findings = [
            f for f in agent.findings if "rate limit" in f.title.lower()
        ]
        assert len(rate_findings) == 0


class TestCORS:
    """Test CORS configuration checks."""

    @pytest.mark.asyncio
    async def test_wildcard_cors(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(200, {"access-control-allow-origin": "*"}, ""),
        ):
            await agent._check_cors(["http://localhost:8080"])

        cors_findings = [
            f for f in agent.findings if "CORS" in f.title
        ]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_cors_origin_reflection(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(
                200,
                {"access-control-allow-origin": "https://evil.example.com"},
                "",
            ),
        ):
            await agent._check_cors(["http://localhost:8080"])

        cors_findings = [
            f for f in agent.findings if "CORS" in f.title
        ]
        assert len(cors_findings) == 1
        assert cors_findings[0].severity == Severity.HIGH


class TestGraphQLIntrospection:
    """Test GraphQL introspection detection."""

    @pytest.mark.asyncio
    async def test_graphql_introspection_enabled(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(
                200,
                {},
                '{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
            ),
        ):
            await agent._check_graphql_introspection(["http://localhost:8080"])

        gql_findings = [
            f for f in agent.findings if "GraphQL" in f.title
        ]
        assert len(gql_findings) == 1

    @pytest.mark.asyncio
    async def test_graphql_introspection_disabled(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch.object(
            agent,
            "_http_request",
            return_value=(400, {}, "Introspection disabled"),
        ):
            await agent._check_graphql_introspection(["http://localhost:8080"])

        gql_findings = [
            f for f in agent.findings if "GraphQL" in f.title
        ]
        assert len(gql_findings) == 0


class TestNucleiIntegration:
    """Test Nuclei integration."""

    @pytest.mark.asyncio
    async def test_nuclei_unavailable(self, scan_context):
        agent = APISecurityAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_nuclei(["http://localhost:8080"])

        assert result is False
