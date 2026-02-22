"""Tests for ResourceExhaustionAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.resource_exhaustion import (
    HTTP_NO_TIMEOUT,
    REDOS_INDICATORS,
    ZIP_PATTERNS,
    ResourceExhaustionAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestResourceExhaustionMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert ResourceExhaustionAgent.name == "resource_exhaustion"

    def test_phase(self):
        assert ResourceExhaustionAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM04" in ResourceExhaustionAgent.frameworks
        assert "ASI10" in ResourceExhaustionAgent.frameworks

    def test_no_dependencies(self):
        assert ResourceExhaustionAgent.depends_on == []


class TestReDoSPatterns:
    """Test ReDoS detection patterns."""

    def test_redos_indicators_defined(self):
        assert len(REDOS_INDICATORS) >= 3

    def test_nested_quantifier_detected(self):
        # (a+)+ pattern
        assert REDOS_INDICATORS[0].search("(a+)+")
        assert REDOS_INDICATORS[0].search("([a-z]+)+")

    def test_alternation_quantifier_detected(self):
        # (a|a)* pattern
        assert REDOS_INDICATORS[1].search("(a|b)*")


class TestHTTPTimeoutPatterns:
    """Test HTTP timeout patterns."""

    def test_timeout_patterns_defined(self):
        assert len(HTTP_NO_TIMEOUT) >= 3

    def test_requests_without_timeout(self):
        _, pattern, _ = HTTP_NO_TIMEOUT[0]
        assert pattern.search('requests.get("http://example.com")')
        assert pattern.search('requests.post("http://example.com", data=payload)')


class TestResourceExhaustionNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestReDoSDetection:
    """Test ReDoS detection in code."""

    @pytest.mark.asyncio
    async def test_detects_redos_pattern(self, scan_context):
        scan_context.container_id = "test-container"
        agent = ResourceExhaustionAgent(scan_context)

        code = (
            'import re\n'
            'pattern = re.compile(r"(a+)+")\n'
            'result = pattern.search(user_input)\n'
        ).encode()

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"/app/main.py\n", b""))
            else:
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(code, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent.analyze()

        redos_findings = [f for f in agent.findings if "ReDoS" in f.title]
        assert len(redos_findings) >= 1


class TestMissingTimeouts:
    """Test missing timeout detection."""

    def test_check_missing_timeouts(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = 'response = requests.get("http://api.example.com")\n'
        agent._check_missing_timeouts(code, "/app/main.py")
        timeout_findings = [f for f in agent.findings if "timeout" in f.title.lower()]
        assert len(timeout_findings) >= 1


class TestUnboundedLoops:
    """Test unbounded loop detection."""

    def test_detects_while_true_no_break(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = (
            'def process():\n'
            '    while True:\n'
            '        do_something()\n'
        )
        agent._check_unbounded_loops(code, "/app/main.py")
        loop_findings = [f for f in agent.findings if "Unbounded loop" in f.title]
        assert len(loop_findings) >= 1

    def test_while_true_with_break_ok(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = (
            'def process():\n'
            '    while True:\n'
            '        if done:\n'
            '            break\n'
        )
        agent._check_unbounded_loops(code, "/app/main.py")
        loop_findings = [f for f in agent.findings if "Unbounded loop" in f.title]
        assert len(loop_findings) == 0

    def test_while_true_with_return_ok(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = (
            'def process():\n'
            '    while True:\n'
            '        if done:\n'
            '            return result\n'
        )
        agent._check_unbounded_loops(code, "/app/main.py")
        loop_findings = [f for f in agent.findings if "Unbounded loop" in f.title]
        assert len(loop_findings) == 0


class TestRecursionLimit:
    """Test recursion limit detection."""

    def test_detects_recursive_without_depth(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = (
            'def traverse(node):\n'
            '    if node.children:\n'
            '        for child in node.children:\n'
            '            traverse(child)\n'
        )
        agent._check_missing_recursion_limit(code, "/app/main.py")
        rec_findings = [f for f in agent.findings if "Recursive" in f.title]
        assert len(rec_findings) >= 1

    def test_recursive_with_depth_ok(self, scan_context):
        agent = ResourceExhaustionAgent(scan_context)
        code = (
            'def traverse(node, depth=0):\n'
            '    if depth > 100:\n'
            '        return\n'
            '    traverse(node.child, depth + 1)\n'
        )
        agent._check_missing_recursion_limit(code, "/app/main.py")
        rec_findings = [f for f in agent.findings if "Recursive" in f.title]
        assert len(rec_findings) == 0
