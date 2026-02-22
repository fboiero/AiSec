"""Deep deserialization attack surface scanning agent."""

from __future__ import annotations

import ast
import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Unsafe deserialization patterns grouped by format
PICKLE_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "pickle.load/loads",
        re.compile(r"pickle\.(?:load|loads)\s*\("),
        Severity.CRITICAL,
        "Use safetensors or json for data serialization. Never unpickle untrusted data.",
    ),
    (
        "torch.load without weights_only",
        re.compile(r"torch\.load\s*\([^)]*\)(?!.*weights_only\s*=\s*True)"),
        Severity.HIGH,
        "Use torch.load(path, weights_only=True) or switch to safetensors.",
    ),
    (
        "joblib.load",
        re.compile(r"joblib\.load\s*\("),
        Severity.HIGH,
        "Use safetensors or validate file integrity before loading with joblib.",
    ),
    (
        "shelve.open",
        re.compile(r"shelve\.open\s*\("),
        Severity.HIGH,
        "shelve uses pickle internally. Use a safer storage format.",
    ),
    (
        "dill.load/loads",
        re.compile(r"dill\.(?:load|loads)\s*\("),
        Severity.CRITICAL,
        "dill extends pickle and can execute arbitrary code. Use safer alternatives.",
    ),
]

YAML_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "yaml.load without SafeLoader",
        re.compile(r"yaml\.load\s*\([^)]*\)(?!.*(?:Safe|CSafe)Loader)"),
        Severity.HIGH,
        "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader).",
    ),
    (
        "yaml.unsafe_load",
        re.compile(r"yaml\.unsafe_load\s*\("),
        Severity.CRITICAL,
        "Replace yaml.unsafe_load with yaml.safe_load.",
    ),
]

XML_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "xml.etree without defusedxml",
        re.compile(r"(?:xml\.etree|xml\.dom|xml\.sax|lxml\.etree)\.(?:parse|fromstring|iterparse)\s*\("),
        Severity.HIGH,
        "Use defusedxml instead of standard XML parsers to prevent XXE attacks.",
    ),
    (
        "External entity reference",
        re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']'),
        Severity.CRITICAL,
        "Remove external entity references. Use defusedxml with external entities disabled.",
    ),
]

JSON_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "jsonpickle.decode",
        re.compile(r"jsonpickle\.(?:decode|loads)\s*\("),
        Severity.CRITICAL,
        "jsonpickle can execute arbitrary code. Use standard json.loads instead.",
    ),
    (
        "Custom object_hook with import",
        re.compile(r"object_hook\s*=.*__import__"),
        Severity.CRITICAL,
        "Remove __import__ from object_hook. Use explicit type mapping instead.",
    ),
]

MODEL_FILE_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "Pickle model file loaded",
        re.compile(r"(?:open|load)\s*\([^)]*\.(?:pkl|pickle|joblib)\b"),
        Severity.HIGH,
        "Use safetensors format for model files instead of pickle-based formats.",
    ),
    (
        "PyTorch model without safetensors",
        re.compile(r"(?:open|load)\s*\([^)]*\.(?:pt|pth|bin)\b"),
        Severity.MEDIUM,
        "Consider using safetensors format for safer model loading.",
    ),
]

PROTOBUF_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "Unbounded protobuf message",
        re.compile(r"ParseFromString\s*\([^)]*\)(?!.*max_size)"),
        Severity.MEDIUM,
        "Set maximum message size for protobuf parsing to prevent memory exhaustion.",
    ),
    (
        "msgpack without max_len",
        re.compile(r"msgpack\.unpack(?:b)?\s*\([^)]*\)(?!.*max_.*_len)"),
        Severity.MEDIUM,
        "Set max_str_len and max_bin_len when unpacking msgpack data.",
    ),
]

ALL_PATTERNS = (
    PICKLE_PATTERNS + YAML_PATTERNS + XML_PATTERNS +
    JSON_PATTERNS + MODEL_FILE_PATTERNS + PROTOBUF_PATTERNS
)


class SerializationAgent(BaseAgent):
    """Deep deserialization attack surface scanner."""

    name: ClassVar[str] = "serialization"
    description: ClassVar[str] = (
        "Scans for unsafe deserialization patterns across pickle, YAML, XML (XXE), "
        "JSON (jsonpickle), protobuf, msgpack, and model file formats. Checks for "
        "custom __reduce__ overrides and missing defusedxml usage."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM06", "ASI05", "ASI06"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Scan for deserialization attack surfaces."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for serialization analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM01"],
            )
            return

        all_hits: list[tuple[str, str, str, Severity, str]] = []
        has_xml_import = False
        has_defusedxml = False
        reduce_overrides: list[tuple[str, int]] = []

        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if not content:
                continue

            # Check for defusedxml usage
            if "defusedxml" in content:
                has_defusedxml = True
            if "xml.etree" in content or "lxml" in content or "xml.dom" in content:
                has_xml_import = True

            # Check for __reduce__ overrides (AST-based)
            reduce_overrides.extend(self._find_reduce_overrides(content, fpath))

            # Pattern matching
            for pattern_name, regex, severity, remediation in ALL_PATTERNS:
                matches = list(regex.finditer(content))
                for m in matches[:3]:
                    start = max(0, m.start() - 30)
                    end = min(len(content), m.end() + 60)
                    snippet = content[start:end].strip().replace("\n", " ")
                    all_hits.append((pattern_name, fpath, snippet, severity, remediation))

        # Report XML without defusedxml
        if has_xml_import and not has_defusedxml:
            self.add_finding(
                title="XML parsing without defusedxml",
                description=(
                    "XML parsing libraries (xml.etree, lxml) are used without "
                    "defusedxml, which leaves the application vulnerable to XXE "
                    "(XML External Entity) and billion laughs attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI05"],
                remediation="pip install defusedxml and replace xml.etree with defusedxml.ElementTree.",
                cvss_score=7.5,
            )

        # Report __reduce__ overrides
        if reduce_overrides:
            details = "\n".join(f"  {f}:{line}" for f, line in reduce_overrides[:10])
            self.add_finding(
                title=f"Custom __reduce__ overrides ({len(reduce_overrides)})",
                description=(
                    f"Found {len(reduce_overrides)} class(es) with custom __reduce__ "
                    "methods. These can execute arbitrary code during pickle "
                    "deserialization."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI05"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="__reduce__ overrides",
                        raw_data=details,
                        location="source files",
                    )
                ],
                remediation="Remove __reduce__ overrides unless absolutely necessary. Use safetensors.",
                cvss_score=7.0,
            )

        # Group and report pattern hits
        if not all_hits:
            return

        by_pattern: dict[str, list[tuple[str, str, Severity, str]]] = {}
        for name, fpath, snippet, sev, rem in all_hits:
            by_pattern.setdefault(name, []).append((fpath, snippet, sev, rem))

        for pattern_name, hits in by_pattern.items():
            worst_sev = min(
                (sev for _, _, sev, _ in hits),
                key=lambda s: list(Severity).index(s),
            )
            details = "\n".join(
                f"  {fpath}: {snippet[:120]}"
                for fpath, snippet, _, _ in hits[:10]
            )

            self.add_finding(
                title=f"Unsafe deserialization: {pattern_name} ({len(hits)} instances)",
                description=(
                    f"Detected {len(hits)} instance(s) of unsafe deserialization "
                    f"pattern '{pattern_name}'. Deserialization of untrusted data "
                    f"can lead to remote code execution."
                ),
                severity=worst_sev,
                owasp_llm=["LLM01", "LLM06"],
                owasp_agentic=["ASI05", "ASI06"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"{len(hits)} matches for '{pattern_name}'",
                        raw_data=details,
                        location=hits[0][0] if hits else "",
                    )
                ],
                remediation=hits[0][3],
                cvss_score=9.0 if worst_sev == Severity.CRITICAL else 7.0,
                ai_risk_score=8.0,
            )

    def _find_reduce_overrides(self, content: str, fpath: str) -> list[tuple[str, int]]:
        """Find classes with __reduce__ method overrides using AST."""
        results: list[tuple[str, int]] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return results

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name in (
                        "__reduce__", "__reduce_ex__"
                    ):
                        results.append((fpath, item.lineno))
        return results

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
