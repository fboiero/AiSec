"""Tests for ToolChainSecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.tool_chain import (
    AGENT_EXECUTOR_PATTERNS,
    ERROR_HANDLING_PATTERNS,
    EXEC_PATTERNS,
    FILE_OPS_PATTERNS,
    MAX_ITER_PATTERNS,
    NETWORK_OPS_PATTERNS,
    PATH_RESTRICT_PATTERNS,
    SANDBOX_PATTERNS,
    SQL_FORMAT_PATTERNS,
    SQL_SAFE_PATTERNS,
    SUBPROCESS_PATTERNS,
    TOOL_AUTH_PATTERNS,
    TOOL_CLASS_PATTERN,
    TOOL_DECORATOR_PATTERN,
    TOOL_LOGGING_PATTERNS,
    TOOL_OUTPUT_TO_PROMPT,
    URL_RESTRICT_PATTERNS,
    ToolChainSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestToolChainMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert ToolChainSecurityAgent.name == "tool_chain"

    def test_phase(self):
        assert ToolChainSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM06" in ToolChainSecurityAgent.frameworks
        assert "ASI02" in ToolChainSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert ToolChainSecurityAgent.depends_on == []


class TestToolChainPatterns:
    """Test regex pattern matching."""

    def test_tool_decorator_matches(self):
        assert TOOL_DECORATOR_PATTERN.search("@tool")
        assert TOOL_DECORATOR_PATTERN.search("@server.tool")

    def test_exec_patterns_match(self):
        assert EXEC_PATTERNS.search("exec(code)")
        assert EXEC_PATTERNS.search("eval(expression)")

    def test_sql_format_matches(self):
        assert SQL_FORMAT_PATTERNS.search('execute(f"SELECT * FROM {table}")')


class TestToolChainNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestCodeExecWithoutSandbox:
    """Test code execution without sandbox detection."""

    def test_detects_exec_without_sandbox(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def run_code(code: str) -> str:\n'
                '    result = exec(code)\n'
                '    return str(result)\n'
            )
        }
        agent._check_code_exec_no_sandbox(files)
        findings = [f for f in agent.findings if "sandbox" in f.title.lower()]
        assert len(findings) >= 1

    def test_exec_with_docker_sandbox_passes(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def run_code(code: str) -> str:\n'
                '    container = docker.run(code)\n'
                '    result = exec(code)\n'
                '    return str(result)\n'
            )
        }
        agent._check_code_exec_no_sandbox(files)
        findings = [f for f in agent.findings if "sandbox" in f.title.lower()]
        assert len(findings) == 0


class TestFileToolsWithoutRestrictions:
    """Test file tools without path restrictions detection."""

    def test_detects_file_ops_without_restriction(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def read_file(path: str) -> str:\n'
                '    return open(path).read()\n'
            )
        }
        agent._check_file_no_restrictions(files)
        findings = [f for f in agent.findings if "File system" in f.title]
        assert len(findings) >= 1


class TestNetworkToolsWithoutAllowlist:
    """Test network tools without URL allowlist detection."""

    def test_detects_network_without_allowlist(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def fetch_url(url: str) -> str:\n'
                '    return requests.get(url).text\n'
            )
        }
        agent._check_network_no_allowlist(files)
        findings = [f for f in agent.findings if "Network" in f.title or "allowlist" in f.title.lower()]
        assert len(findings) >= 1


class TestSQLInjection:
    """Test SQL injection in tools detection."""

    def test_detects_sql_injection(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def query_db(table: str) -> str:\n'
                '    cursor.execute(f"SELECT * FROM {table}")\n'
                '    return cursor.fetchall()\n'
            )
        }
        agent._check_sql_injection(files)
        findings = [f for f in agent.findings if "SQL" in f.title]
        assert len(findings) >= 1

    def test_parameterized_sql_with_orm_passes(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def query_db(user_id: int) -> str:\n'
                '    result = session.query(User).filter_by(id=user_id).all()\n'
                '    return str(result)\n'
            )
        }
        agent._check_sql_injection(files)
        findings = [f for f in agent.findings if "SQL" in f.title]
        assert len(findings) == 0


class TestToolOutputInjection:
    """Test tool output injection detection."""

    def test_detects_output_injection(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/agent.py": (
                '@tool\n'
                'def search(query: str) -> str:\n'
                '    return db.search(query)\n'
                '\n'
                'messages.append({"role": "tool", "content": tool_result})\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_output_injection(files, combined)
        findings = [f for f in agent.findings if "output injection" in f.title.lower() or "Tool output" in f.title]
        assert len(findings) >= 1


class TestUnrestrictedChaining:
    """Test unrestricted tool chaining detection."""

    def test_detects_unrestricted_chaining(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        combined = (
            'from langchain.agents import AgentExecutor\n'
            'executor = AgentExecutor(agent=agent, tools=tools)\n'
            'result = executor.invoke({"input": query})\n'
        )
        agent._check_unrestricted_chaining(combined)
        findings = [f for f in agent.findings if "chaining" in f.title.lower()]
        assert len(findings) >= 1


class TestMissingErrorHandling:
    """Test missing error handling detection."""

    def test_detects_missing_error_handling(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def dangerous_op(data: str) -> str:\n'
                '    return process(data)\n'
            )
        }
        agent._check_error_handling(files)
        findings = [f for f in agent.findings if "error handling" in f.title.lower()]
        assert len(findings) >= 1


class TestPrivilegedToolWithoutAuth:
    """Test privileged tool without auth detection."""

    def test_detects_privileged_no_auth(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        files = {
            "/app/tools.py": (
                '@tool\n'
                'def delete_record(record_id: str) -> str:\n'
                '    db.delete(record_id)\n'
                '    return "deleted"\n'
            )
        }
        agent._check_privileged_no_auth(files)
        findings = [f for f in agent.findings if "Privileged" in f.title]
        assert len(findings) >= 1


class TestToolLogging:
    """Test tool logging absence detection."""

    def test_detects_no_logging(self, scan_context):
        agent = ToolChainSecurityAgent(scan_context)
        combined = (
            '@tool\n'
            'def my_tool(data: str) -> str:\n'
            '    return process(data)\n'
        )
        agent._check_tool_logging(combined)
        findings = [f for f in agent.findings if "logging" in f.title.lower() or "audit" in f.title.lower()]
        assert len(findings) >= 1
