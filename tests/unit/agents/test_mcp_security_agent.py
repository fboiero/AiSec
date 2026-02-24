"""Tests for MCPSecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.mcp_security import (
    APPROVAL_PATTERNS,
    HTTP_TRANSPORT_PATTERNS,
    MCP_AUTH_PATTERNS,
    MCP_DEBUG_PATTERNS,
    MCP_SECRET_PATTERNS,
    MCP_SERVER_PATTERNS,
    MCP_TOOL_PATTERNS,
    OUTPUT_SANITIZATION_PATTERNS,
    PATH_VALIDATION_PATTERNS,
    RATE_LIMIT_PATTERNS,
    RESOURCE_URI_PATTERNS,
    SENSITIVE_TOOL_OPS,
    TLS_PATTERNS,
    TOOL_ALLOWLIST_PATTERNS,
    TOOL_VALIDATION_PATTERNS,
    MCPSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestMCPSecurityMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert MCPSecurityAgent.name == "mcp_security"

    def test_phase(self):
        assert MCPSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "ASI01" in MCPSecurityAgent.frameworks
        assert "ASI02" in MCPSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert MCPSecurityAgent.depends_on == []


class TestMCPPatterns:
    """Test MCP regex pattern matching."""

    def test_server_patterns_match(self):
        assert MCP_SERVER_PATTERNS.search("from mcp.server import Server")
        assert MCP_SERVER_PATTERNS.search("app = FastMCP('myserver')")

    def test_tool_patterns_match(self):
        assert MCP_TOOL_PATTERNS.search("@server.tool(")
        assert MCP_TOOL_PATTERNS.search("@mcp.tool(")

    def test_auth_patterns_match(self):
        assert MCP_AUTH_PATTERNS.search("@server.auth")
        assert MCP_AUTH_PATTERNS.search("auth_handler = verify_token")


class TestMCPSecurityNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestUnauthenticatedServer:
    """Test unauthenticated MCP server detection."""

    def test_detects_unauthenticated_server(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from mcp.server import Server\n'
                'server = Server("my-server")\n'
                '@server.tool()\n'
                'def my_tool(query: str) -> str:\n'
                '    return "result"\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unauthenticated_server(files, combined)
        findings = [f for f in agent.findings if "Unauthenticated" in f.title]
        assert len(findings) >= 1

    def test_server_with_auth_passes(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from mcp.server import Server\n'
                'server = Server("my-server")\n'
                '@server.auth\n'
                'def auth_handler(token):\n'
                '    return verify_token(token)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unauthenticated_server(files, combined)
        findings = [f for f in agent.findings if "Unauthenticated" in f.title]
        assert len(findings) == 0


class TestPermissiveSchemas:
    """Test overly permissive tool schema detection."""

    def test_detects_permissive_schemas(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                'from mcp.server import Server\n'
                'server = Server("tools")\n'
                '@server.tool()\n'
                'def search(query: str) -> str:\n'
                '    return results\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_permissive_schemas(files, combined)
        findings = [f for f in agent.findings if "permissive" in f.title.lower()]
        assert len(findings) >= 1

    def test_schemas_with_annotated_validation_pass(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                'from mcp.server import Server\n'
                'from typing import Annotated\n'
                'from pydantic import Field\n'
                'server = Server("tools")\n'
                '@server.tool()\n'
                'def search(query: Annotated[str, Field(max_length=500)]) -> str:\n'
                '    return results\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_permissive_schemas(files, combined)
        findings = [f for f in agent.findings if "permissive" in f.title.lower()]
        assert len(findings) == 0


class TestUnrestrictedAccess:
    """Test unrestricted tool access detection."""

    def test_detects_unrestricted_access(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        combined = (
            'from mcp.server import Server\n'
            'server = Server("tools")\n'
            '@server.tool()\n'
            'def dangerous_tool(cmd: str) -> str:\n'
            '    return exec(cmd)\n'
        )
        agent._check_unrestricted_access(combined)
        findings = [f for f in agent.findings if "Unrestricted" in f.title]
        assert len(findings) >= 1


class TestInsecureTransport:
    """Test insecure HTTP transport detection."""

    def test_detects_insecure_http(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from mcp.server import Server\n'
                'server = Server("my-server")\n'
                'transport = SSEServerTransport()\n'
                'server.run(host="0.0.0.0", port=8080)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_insecure_transport(files, combined)
        findings = [f for f in agent.findings if "transport" in f.title.lower()]
        assert len(findings) >= 1

    def test_transport_with_tls_passes(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from mcp.server import Server\n'
                'server = Server("my-server")\n'
                'transport = SSEServerTransport()\n'
                'ssl_context = ssl.create_default_context()\n'
                'server.run(host="0.0.0.0", port=8080, ssl=ssl_context)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_insecure_transport(files, combined)
        findings = [f for f in agent.findings if "transport" in f.title.lower()]
        assert len(findings) == 0


class TestRateLimiting:
    """Test missing rate limiting detection."""

    def test_detects_missing_rate_limiting(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        combined = (
            'from mcp.server import Server\n'
            'server = Server("tools")\n'
            '@server.tool()\n'
            'def my_tool(query: str) -> str:\n'
            '    return "result"\n'
        )
        agent._check_rate_limiting(combined)
        findings = [f for f in agent.findings if "rate" in f.title.lower()]
        assert len(findings) >= 1


class TestSensitiveToolsWithoutApproval:
    """Test sensitive tools without approval detection."""

    def test_detects_sensitive_tools_no_approval(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                'from mcp.server import Server\n'
                'server = Server("tools")\n'
                '@server.tool()\n'
                'def run_code(code: str) -> str:\n'
                '    return eval(code)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_missing_approval(files, combined)
        findings = [f for f in agent.findings if "approval" in f.title.lower()]
        assert len(findings) >= 1


class TestResourceURIPathValidation:
    """Test resource URI path traversal detection."""

    def test_detects_resource_without_path_validation(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/resources.py": (
                'from mcp.server import Server\n'
                'server = Server("resources")\n'
                '@server.resource(\n'
                '    uri="file:///{path}"\n'
                ')\n'
                'def read_file(path: str) -> str:\n'
                '    return open(path).read()\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_resource_path_traversal(files, combined)
        findings = [f for f in agent.findings if "path traversal" in f.title.lower()]
        assert len(findings) >= 1


class TestOutputSanitization:
    """Test missing output sanitization detection."""

    def test_detects_no_output_sanitization(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                'from mcp.server import Server\n'
                'server = Server("tools")\n'
                '@server.tool()\n'
                'def read_data(query: str) -> str:\n'
                '    return db.execute(query)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_output_sanitization(files, combined)
        findings = [f for f in agent.findings if "sanitization" in f.title.lower()]
        assert len(findings) >= 1


class TestSecretsInConfig:
    """Test secrets in MCP config detection."""

    def test_detects_secrets_in_config(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/mcp_config.yaml": (
                'mcp:\n'
                '  server: my-server\n'
                '  api_key: "sk-abcdef1234567890abcdefgh1234"\n'
            )
        }
        agent._check_secrets_in_config(files)
        findings = [f for f in agent.findings if "Secrets" in f.title]
        assert len(findings) >= 1


class TestDebugEndpoints:
    """Test debug endpoint detection."""

    def test_detects_debug_endpoints(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/server.py": (
                'from mcp.server import Server\n'
                'server = Server("debug-server")\n'
                'server.run(debug=True)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_debug_endpoints(files, combined)
        findings = [f for f in agent.findings if "debug" in f.title.lower()]
        assert len(findings) >= 1


class TestNoMCPPatternsNoFindings:
    """Test that non-MCP code produces no findings."""

    def test_no_mcp_patterns(self, scan_context):
        agent = MCPSecurityAgent(scan_context)
        files = {
            "/app/main.py": (
                'import json\n'
                'data = json.loads(response)\n'
                'print(data)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unauthenticated_server(files, combined)
        agent._check_permissive_schemas(files, combined)
        agent._check_unrestricted_access(combined)
        assert len(agent.findings) == 0
