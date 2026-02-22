"""Reusable AST-based taint propagation engine.

Provides source-to-sink taint tracking by parsing Python AST, identifying
taint sources (untrusted data entry points) and sinks (dangerous operations),
and propagating taint through assignments, function calls, and returns.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

from aisec.core.enums import Severity

logger = logging.getLogger(__name__)


@dataclass
class TaintSource:
    """An untrusted data entry point."""

    name: str
    patterns: list[str]  # AST attribute patterns that introduce taint
    severity: Severity = Severity.HIGH


@dataclass
class TaintSink:
    """A dangerous destination for tainted data."""

    name: str
    patterns: list[str]  # AST patterns that consume tainted data
    severity: Severity = Severity.CRITICAL


@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""

    source: TaintSource
    sink: TaintSink
    path: list[str]  # Variable/function chain from source to sink
    file: str
    line_start: int
    line_end: int


# Default sources: untrusted data entry points
DEFAULT_SOURCES: list[TaintSource] = [
    TaintSource("flask_request", ["request.json", "request.form", "request.args", "request.data", "request.get_json"], Severity.HIGH),
    TaintSource("user_input", ["input", "sys.stdin"], Severity.HIGH),
    TaintSource("llm_response", ["openai.ChatCompletion", "anthropic.messages", "response.choices", "completion.choices", "chat_completion"], Severity.CRITICAL),
    TaintSource("tool_output", ["tool_output", "function_result", "tool_result", "action_result"], Severity.HIGH),
    TaintSource("env_var", ["os.environ", "os.getenv"], Severity.MEDIUM),
    TaintSource("fastapi_param", ["request.query_params", "request.path_params", "request.body"], Severity.HIGH),
]

# Default sinks: dangerous destinations
DEFAULT_SINKS: list[TaintSink] = [
    TaintSink("code_execution", ["eval", "exec", "compile"], Severity.CRITICAL),
    TaintSink("command_injection", ["subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call", "os.system", "os.popen"], Severity.CRITICAL),
    TaintSink("sql_injection", ["cursor.execute", "connection.execute", "engine.execute", "session.execute", "raw", "rawquery"], Severity.CRITICAL),
    TaintSink("template_injection", ["render_template_string", "Template", "Jinja2"], Severity.HIGH),
    TaintSink("deserialization", ["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load"], Severity.HIGH),
    TaintSink("file_write", ["open", "write", "writelines"], Severity.MEDIUM),
    TaintSink("path_traversal", ["os.path.join", "pathlib.Path"], Severity.MEDIUM),
]


class _TaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint propagation."""

    def __init__(
        self,
        sources: list[TaintSource],
        sinks: list[TaintSink],
        filename: str,
    ) -> None:
        self.sources = sources
        self.sinks = sinks
        self.filename = filename
        self.tainted_vars: dict[str, TaintSource] = {}
        self.flows: list[TaintFlow] = []

    def _match_source(self, node: ast.AST) -> TaintSource | None:
        """Check if an AST node matches any taint source pattern."""
        code = ast.dump(node)
        node_str = self._node_to_string(node)
        for source in self.sources:
            for pattern in source.patterns:
                if pattern in node_str or pattern in code:
                    return source
        return None

    def _match_sink(self, node: ast.AST) -> TaintSink | None:
        """Check if an AST node matches any taint sink pattern."""
        node_str = self._node_to_string(node)
        for sink in self.sinks:
            for pattern in sink.patterns:
                if pattern in node_str:
                    return sink
        return None

    def _node_to_string(self, node: ast.AST) -> str:
        """Convert an AST node to a readable string representation."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value = self._node_to_string(node.value)
            return f"{value}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._node_to_string(node.func)
        if isinstance(node, ast.Subscript):
            return self._node_to_string(node.value)
        if isinstance(node, ast.Constant):
            return repr(node.value)
        return ast.dump(node)

    def _is_tainted(self, node: ast.AST) -> TaintSource | None:
        """Check if an AST node references tainted data."""
        # Direct source match
        source = self._match_source(node)
        if source:
            return source

        # Check if it's a tainted variable
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return self.tainted_vars[node.id]

        # Check attribute access on tainted variable
        if isinstance(node, ast.Attribute):
            return self._is_tainted(node.value)

        # Check subscript on tainted variable
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)

        # Check function calls that return tainted values
        if isinstance(node, ast.Call):
            source = self._match_source(node.func)
            if source:
                return source
            # Check if any argument is tainted
            for arg in node.args:
                t = self._is_tainted(arg)
                if t:
                    return t
            for kw in node.keywords:
                t = self._is_tainted(kw.value)
                if t:
                    return t

        return None

    def _check_sink_args(self, node: ast.Call, sink: TaintSink) -> None:
        """Check if any argument to a sink call is tainted."""
        for arg in node.args:
            source = self._is_tainted(arg)
            if source:
                var_chain = [self._node_to_string(arg)]
                self.flows.append(TaintFlow(
                    source=source,
                    sink=sink,
                    path=var_chain,
                    file=self.filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                ))
                return
        for kw in node.keywords:
            source = self._is_tainted(kw.value)
            if source:
                var_chain = [kw.arg or "**kwargs", self._node_to_string(kw.value)]
                self.flows.append(TaintFlow(
                    source=source,
                    sink=sink,
                    path=var_chain,
                    file=self.filename,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                ))
                return

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track taint through assignments."""
        source = self._is_tainted(node.value)
        if source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = source
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_vars[elt.id] = source
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Track taint through annotated assignments."""
        if node.value:
            source = self._is_tainted(node.value)
            if source and isinstance(node.target, ast.Name):
                self.tainted_vars[node.target.id] = source
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check if a call is a sink receiving tainted data."""
        sink = self._match_sink(node.func)
        if sink:
            self._check_sink_args(node, sink)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function parameters that could be tainted."""
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function parameters."""
        self.generic_visit(node)


def analyze_taint(
    source_code: str,
    sources: list[TaintSource] | None = None,
    sinks: list[TaintSink] | None = None,
    filename: str = "<unknown>",
) -> list[TaintFlow]:
    """Parse AST, propagate taint through assignments and calls, return source-to-sink flows.

    Args:
        source_code: Python source code to analyze.
        sources: Taint sources to track. Defaults to DEFAULT_SOURCES.
        sinks: Taint sinks to check. Defaults to DEFAULT_SINKS.
        filename: Filename for reporting.

    Returns:
        List of detected taint flows from source to sink.
    """
    if sources is None:
        sources = DEFAULT_SOURCES
    if sinks is None:
        sinks = DEFAULT_SINKS

    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError:
        logger.debug("Failed to parse %s for taint analysis", filename)
        return []

    visitor = _TaintVisitor(sources, sinks, filename)
    visitor.visit(tree)
    return visitor.flows
