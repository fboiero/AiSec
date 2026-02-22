"""Tests for TaintAnalysisAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.taint_analysis import (
    AI_SINKS,
    AI_SOURCES,
    TaintAnalysisAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase, Severity


class TestTaintAnalysisAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert TaintAnalysisAgent.name == "taint_analysis"

    def test_phase(self):
        assert TaintAnalysisAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM01" in TaintAnalysisAgent.frameworks
        assert "ASI01" in TaintAnalysisAgent.frameworks

    def test_depends_on(self):
        assert "static_analysis" in TaintAnalysisAgent.depends_on

    def test_ai_sources_defined(self):
        assert len(AI_SOURCES) > 0

    def test_ai_sinks_defined(self):
        assert len(AI_SINKS) > 0


class TestTaintAnalysisNoContainer:
    """Test agent behavior without a container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = TaintAnalysisAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO
        assert "No source" in agent.findings[0].title

    @pytest.mark.asyncio
    async def test_no_files_found(self, scan_context):
        scan_context.container_id = "test-container"
        agent = TaintAnalysisAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            await agent.analyze()

        assert len(agent.findings) == 1
        assert "No source" in agent.findings[0].title


class TestTaintAnalysisWithCode:
    """Test taint analysis on source code."""

    @pytest.mark.asyncio
    async def test_detects_eval_taint_flow(self, scan_context):
        scan_context.container_id = "test-container"
        agent = TaintAnalysisAgent(scan_context)

        dangerous_code = (
            'user_data = input("Enter: ")\n'
            'result = eval(user_data)\n'
        ).encode()

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:  # find files
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"/app/main.py\n", b""))
            else:  # read file
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(dangerous_code, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent.analyze()

        taint_findings = [f for f in agent.findings if "Taint flow" in f.title]
        assert len(taint_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_flows_clean_code(self, scan_context):
        scan_context.container_id = "test-container"
        agent = TaintAnalysisAgent(scan_context)

        clean_code = (
            'x = 1\n'
            'y = x + 2\n'
            'print(y)\n'
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
                proc.communicate = AsyncMock(return_value=(clean_code, b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            await agent.analyze()

        taint_findings = [f for f in agent.findings if "Taint flow" in f.title]
        assert len(taint_findings) == 0


class TestRemediation:
    """Test remediation advice."""

    def test_remediation_for_known_sinks(self, scan_context):
        agent = TaintAnalysisAgent(scan_context)
        known_sinks = [
            "code_execution", "command_injection", "sql_injection",
            "template_injection", "deserialization", "file_write",
            "prompt_construction", "model_loading", "file_inclusion",
        ]
        for sink in known_sinks:
            rem = agent._remediation_for_sink(sink)
            assert len(rem) > 0

    def test_remediation_for_unknown_sink(self, scan_context):
        agent = TaintAnalysisAgent(scan_context)
        rem = agent._remediation_for_sink("unknown_sink_xyz")
        assert "Review" in rem
