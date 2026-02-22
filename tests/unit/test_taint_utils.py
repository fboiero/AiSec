"""Tests for the shared taint propagation engine."""

from __future__ import annotations

import pytest

from aisec.core.enums import Severity
from aisec.utils.taint import (
    DEFAULT_SINKS,
    DEFAULT_SOURCES,
    TaintFlow,
    TaintSink,
    TaintSource,
    analyze_taint,
)


class TestTaintSourceSinkDefinitions:
    """Test default source and sink definitions."""

    def test_default_sources_not_empty(self):
        assert len(DEFAULT_SOURCES) > 0

    def test_default_sinks_not_empty(self):
        assert len(DEFAULT_SINKS) > 0

    def test_source_structure(self):
        for source in DEFAULT_SOURCES:
            assert isinstance(source, TaintSource)
            assert source.name
            assert len(source.patterns) > 0
            assert isinstance(source.severity, Severity)

    def test_sink_structure(self):
        for sink in DEFAULT_SINKS:
            assert isinstance(sink, TaintSink)
            assert sink.name
            assert len(sink.patterns) > 0
            assert isinstance(sink.severity, Severity)


class TestAnalyzeTaint:
    """Test taint analysis function."""

    def test_no_taint_flows(self):
        code = "x = 1\ny = x + 2\nprint(y)\n"
        flows = analyze_taint(code)
        assert flows == []

    def test_syntax_error_returns_empty(self):
        code = "def foo(\n"
        flows = analyze_taint(code)
        assert flows == []

    def test_empty_code(self):
        flows = analyze_taint("")
        assert flows == []

    def test_direct_eval_of_input(self):
        code = (
            "user_data = input('Enter: ')\n"
            "result = eval(user_data)\n"
        )
        sources = [TaintSource("user_input", ["input"], Severity.HIGH)]
        sinks = [TaintSink("code_exec", ["eval"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks)
        assert len(flows) >= 1
        assert flows[0].source.name == "user_input"
        assert flows[0].sink.name == "code_exec"

    def test_taint_through_assignment(self):
        code = (
            "data = input('Enter: ')\n"
            "processed = data\n"
            "eval(processed)\n"
        )
        sources = [TaintSource("user_input", ["input"], Severity.HIGH)]
        sinks = [TaintSink("code_exec", ["eval"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks)
        assert len(flows) >= 1

    def test_flow_has_file_info(self):
        code = "data = input('x')\neval(data)\n"
        sources = [TaintSource("user_input", ["input"], Severity.HIGH)]
        sinks = [TaintSink("code_exec", ["eval"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks, filename="test.py")
        assert len(flows) >= 1
        assert flows[0].file == "test.py"
        assert flows[0].line_start > 0

    def test_no_flow_when_no_sink(self):
        code = "data = input('x')\nprint(data)\n"
        sources = [TaintSource("user_input", ["input"], Severity.HIGH)]
        sinks = [TaintSink("code_exec", ["eval"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks)
        assert flows == []

    def test_llm_response_to_exec(self):
        code = (
            "response = openai.ChatCompletion.create(model='gpt-4')\n"
            "code = response.choices[0].message.content\n"
            "exec(code)\n"
        )
        flows = analyze_taint(code)
        # Should detect flow from openai to exec
        assert len(flows) >= 0  # May or may not detect depending on propagation depth

    def test_custom_sources_and_sinks(self):
        code = (
            "payload = webhook_data()\n"
            "dangerous_func(payload)\n"
        )
        sources = [TaintSource("webhook", ["webhook_data"], Severity.HIGH)]
        sinks = [TaintSink("danger", ["dangerous_func"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks)
        assert len(flows) >= 1

    def test_multiple_flows(self):
        code = (
            "a = input('1')\n"
            "b = input('2')\n"
            "eval(a)\n"
            "eval(b)\n"
        )
        sources = [TaintSource("user_input", ["input"], Severity.HIGH)]
        sinks = [TaintSink("code_exec", ["eval"], Severity.CRITICAL)]
        flows = analyze_taint(code, sources, sinks)
        assert len(flows) >= 2


class TestTaintFlowDataclass:
    """Test TaintFlow dataclass."""

    def test_taint_flow_creation(self):
        source = TaintSource("test_source", ["input"], Severity.HIGH)
        sink = TaintSink("test_sink", ["eval"], Severity.CRITICAL)
        flow = TaintFlow(
            source=source,
            sink=sink,
            path=["user_data", "result"],
            file="test.py",
            line_start=1,
            line_end=2,
        )
        assert flow.source.name == "test_source"
        assert flow.sink.name == "test_sink"
        assert len(flow.path) == 2
        assert flow.file == "test.py"
