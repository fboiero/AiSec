"""Tests for SerializationAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.serialization import (
    ALL_PATTERNS,
    PICKLE_PATTERNS,
    XML_PATTERNS,
    YAML_PATTERNS,
    SerializationAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestSerializationAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert SerializationAgent.name == "serialization"

    def test_phase(self):
        assert SerializationAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM01" in SerializationAgent.frameworks
        assert "ASI05" in SerializationAgent.frameworks

    def test_no_dependencies(self):
        assert SerializationAgent.depends_on == []


class TestSerializationPatterns:
    """Test pattern matching definitions."""

    def test_all_patterns_not_empty(self):
        assert len(ALL_PATTERNS) > 10

    def test_pickle_load_matches(self):
        _, pattern, _, _ = PICKLE_PATTERNS[0]
        assert pattern.search("data = pickle.load(f)")
        assert pattern.search("obj = pickle.loads(raw)")

    def test_yaml_load_matches(self):
        _, pattern, _, _ = YAML_PATTERNS[0]
        assert pattern.search("yaml.load(data)")

    def test_xml_parse_matches(self):
        _, pattern, _, _ = XML_PATTERNS[0]
        assert pattern.search("xml.etree.parse(file)")
        assert pattern.search("lxml.etree.fromstring(data)")

    def test_pattern_structure(self):
        for name, regex, severity, remediation in ALL_PATTERNS:
            assert isinstance(name, str)
            assert hasattr(regex, "search")
            assert isinstance(severity, Severity)
            assert isinstance(remediation, str)


class TestSerializationNoContainer:
    """Test agent behavior without a container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = SerializationAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_no_files_found(self, scan_context):
        scan_context.container_id = "test-container"
        agent = SerializationAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            await agent.analyze()

        assert len(agent.findings) == 1


class TestSerializationScanning:
    """Test serialization scanning functionality."""

    @pytest.mark.asyncio
    async def test_detects_pickle_usage(self, scan_context):
        scan_context.container_id = "test-container"
        agent = SerializationAgent(scan_context)

        code = (
            'import pickle\n'
            'with open("data.pkl", "rb") as f:\n'
            '    data = pickle.load(f)\n'
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

        pickle_findings = [f for f in agent.findings if "pickle" in f.title.lower()]
        assert len(pickle_findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_xml_without_defusedxml(self, scan_context):
        scan_context.container_id = "test-container"
        agent = SerializationAgent(scan_context)

        code = (
            'from xml.etree import ElementTree\n'
            'tree = xml.etree.parse("data.xml")\n'
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

        xml_findings = [f for f in agent.findings if "xml" in f.title.lower() or "XML" in f.title]
        assert len(xml_findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_reduce_override(self, scan_context):
        scan_context.container_id = "test-container"
        agent = SerializationAgent(scan_context)

        code = (
            'class Exploit:\n'
            '    def __reduce__(self):\n'
            '        return (os.system, ("rm -rf /",))\n'
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

        reduce_findings = [f for f in agent.findings if "__reduce__" in f.title]
        assert len(reduce_findings) >= 1


class TestReduceOverrideDetection:
    """Test __reduce__ override AST detection."""

    def test_find_reduce_overrides(self, scan_context):
        agent = SerializationAgent(scan_context)
        code = (
            'class Foo:\n'
            '    def __reduce__(self):\n'
            '        return (str, ("hello",))\n'
        )
        results = agent._find_reduce_overrides(code, "test.py")
        assert len(results) == 1
        assert results[0][0] == "test.py"

    def test_no_reduce_override(self, scan_context):
        agent = SerializationAgent(scan_context)
        code = 'class Foo:\n    def hello(self):\n        pass\n'
        results = agent._find_reduce_overrides(code, "test.py")
        assert len(results) == 0

    def test_syntax_error(self, scan_context):
        agent = SerializationAgent(scan_context)
        results = agent._find_reduce_overrides("def foo(\n", "test.py")
        assert results == []
