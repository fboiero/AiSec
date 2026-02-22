"""AST-based source-to-sink taint tracking agent."""

from __future__ import annotations

import asyncio
import logging
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence
from aisec.utils.taint import (
    DEFAULT_SINKS,
    DEFAULT_SOURCES,
    TaintFlow,
    TaintSink,
    TaintSource,
    analyze_taint,
)

logger = logging.getLogger(__name__)

# AI-specific taint sources beyond the defaults
AI_SOURCES: list[TaintSource] = [
    TaintSource(
        "langchain_output",
        ["chain.run", "chain.invoke", "agent.run", "llm.predict", "llm.invoke"],
        Severity.HIGH,
    ),
    TaintSource(
        "retrieval_output",
        ["retriever.get_relevant_documents", "vectorstore.similarity_search",
         "index.query", "collection.query"],
        Severity.MEDIUM,
    ),
    TaintSource(
        "webhook_payload",
        ["request.get_json", "request.json", "event.body", "payload"],
        Severity.HIGH,
    ),
]

# Additional dangerous sinks for AI applications
AI_SINKS: list[TaintSink] = [
    TaintSink(
        "prompt_construction",
        ["format_prompt", "PromptTemplate", "ChatPromptTemplate",
         "SystemMessage", "HumanMessage"],
        Severity.HIGH,
    ),
    TaintSink(
        "model_loading",
        ["torch.load", "joblib.load", "tf.saved_model.load"],
        Severity.HIGH,
    ),
    TaintSink(
        "file_inclusion",
        ["importlib.import_module", "__import__", "importlib.reload"],
        Severity.CRITICAL,
    ),
]

# File extensions to analyze
SOURCE_EXTENSIONS = {"*.py"}


class TaintAnalysisAgent(BaseAgent):
    """Source-to-sink taint tracking of untrusted data flows."""

    name: ClassVar[str] = "taint_analysis"
    description: ClassVar[str] = (
        "Performs AST-based taint analysis to track untrusted data (LLM outputs, "
        "user input, tool results) flowing to dangerous functions (eval, exec, "
        "SQL queries, subprocess calls) without sanitization."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM02", "ASI01", "ASI02"]
    depends_on: ClassVar[list[str]] = ["static_analysis"]

    async def analyze(self) -> None:
        """Run taint analysis on source files."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files found for taint analysis",
                description=(
                    "No Python source files were found in the container. "
                    "Taint analysis could not be performed."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM01"],
            )
            return

        all_sources = DEFAULT_SOURCES + AI_SOURCES
        all_sinks = DEFAULT_SINKS + AI_SINKS

        all_flows: list[TaintFlow] = []
        files_analyzed = 0

        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if not content:
                continue
            files_analyzed += 1
            flows = analyze_taint(content, all_sources, all_sinks, filename=fpath)
            all_flows.extend(flows)

        if not all_flows:
            if files_analyzed > 0:
                self.add_finding(
                    title="No taint flows detected",
                    description=(
                        f"Analyzed {files_analyzed} Python files. No untrusted data "
                        "flows to dangerous sinks were detected."
                    ),
                    severity=Severity.INFO,
                    owasp_llm=["LLM01"],
                )
            return

        # Group flows by sink type for consolidated reporting
        by_sink: dict[str, list[TaintFlow]] = {}
        for flow in all_flows:
            by_sink.setdefault(flow.sink.name, []).append(flow)

        for sink_name, flows in by_sink.items():
            worst_severity = min(
                (f.sink.severity for f in flows),
                key=lambda s: list(Severity).index(s),
            )

            flow_details = []
            for f in flows[:10]:
                path_str = " -> ".join(f.path)
                flow_details.append(
                    f"  {f.file}:{f.line_start}: {f.source.name} -> {path_str} -> {sink_name}"
                )
            details = "\n".join(flow_details)

            source_types = list({f.source.name for f in flows})

            self.add_finding(
                title=f"Taint flow to {sink_name} ({len(flows)} paths)",
                description=(
                    f"Detected {len(flows)} untrusted data flow(s) from "
                    f"{', '.join(source_types)} to {sink_name} without sanitization. "
                    f"This may allow code injection, command injection, or data corruption."
                ),
                severity=worst_severity,
                owasp_llm=["LLM01", "LLM02"],
                owasp_agentic=["ASI01", "ASI02"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(flows)} taint flows to {sink_name}",
                        raw_data=details,
                        location=flows[0].file if flows else "",
                    )
                ],
                remediation=self._remediation_for_sink(sink_name),
                cvss_score=9.0 if worst_severity == Severity.CRITICAL else 7.0,
                ai_risk_score=9.0 if "llm" in source_types[0].lower() else 7.0,
            )

    def _remediation_for_sink(self, sink_name: str) -> str:
        """Return sink-specific remediation advice."""
        remediations = {
            "code_execution": (
                "Never pass untrusted data to eval/exec/compile. Use "
                "ast.literal_eval() for safe data parsing. Validate and "
                "sanitize all LLM outputs before execution."
            ),
            "command_injection": (
                "Use subprocess with shell=False and pass arguments as a list. "
                "Never interpolate untrusted data into shell commands. Use "
                "shlex.quote() if shell strings are unavoidable."
            ),
            "sql_injection": (
                "Use parameterized queries instead of string interpolation. "
                "Never pass untrusted data directly to cursor.execute()."
            ),
            "template_injection": (
                "Use render_template() with named templates instead of "
                "render_template_string(). Sanitize user input before template rendering."
            ),
            "deserialization": (
                "Never deserialize untrusted data with pickle/yaml.load. "
                "Use yaml.safe_load() and safetensors for model files."
            ),
            "file_write": (
                "Validate file paths against a whitelist. Use os.path.realpath() "
                "to prevent path traversal. Never write untrusted data to arbitrary paths."
            ),
            "prompt_construction": (
                "Sanitize and validate all data before including it in prompts. "
                "Use structured prompt templates with explicit variable validation."
            ),
            "model_loading": (
                "Use safetensors format instead of pickle-based model files. "
                "Verify model file integrity with checksums before loading."
            ),
            "file_inclusion": (
                "Never dynamically import modules based on untrusted input. "
                "Use a whitelist of allowed module names."
            ),
        }
        return remediations.get(sink_name, "Review and sanitize all data flows to this sink.")

    async def _collect_source_files(self) -> list[str]:
        """Collect Python source file paths from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f -name '*.py' "
            "-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _read_file(self, fpath: str) -> str:
        """Read a file from the container."""
        cid = self.context.container_id
        if not cid:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "head", "-c", "65536", fpath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return ""
            return stdout.decode(errors="replace")
        except Exception:
            return ""
