"""Output security analysis agent."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# HTML/JS injection patterns in output
OUTPUT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "HTML tag injection",
        re.compile(r"<\s*(script|iframe|object|embed|form|input|img\s+[^>]*onerror)\b", re.IGNORECASE),
        "HTML tags that can execute JavaScript or embed external content",
    ),
    (
        "JavaScript event handler",
        re.compile(r"\bon\w+\s*=\s*['\"]", re.IGNORECASE),
        "Inline JavaScript event handlers (onclick, onerror, etc.)",
    ),
    (
        "JavaScript URI",
        re.compile(r"javascript\s*:", re.IGNORECASE),
        "JavaScript: URI scheme for code execution",
    ),
    (
        "Data URI with script",
        re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
        "Data URI that can embed HTML with scripts",
    ),
    (
        "SVG with script",
        re.compile(r"<\s*svg\b[^>]*>.*?<\s*script", re.IGNORECASE | re.DOTALL),
        "SVG elements can contain embedded scripts",
    ),
]

# PII patterns for output leakage detection (subset focused on outputs)
OUTPUT_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[\s.-]?\d{4}[\s.-]?\d{4}[\s.-]?\d{1,4}\b"
    ),
}

# Patterns indicating output sanitization
SANITIZATION_PATTERNS = [
    re.compile(r"(?i)(html\.escape|escape_html|sanitize|bleach|dompurify)"),
    re.compile(r"(?i)(markupsafe|jinja2.*autoescape|auto_escape\s*=\s*True)"),
    re.compile(r"(?i)(content.security.policy|CSP|X-Content-Type-Options)"),
    re.compile(r"(?i)(output.filter|output.valid|response.sanitiz|clean.output)"),
    re.compile(r"(?i)(strip_tags|remove_html|encode_html|html_entities)"),
]

# Error information disclosure patterns
ERROR_DISCLOSURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Stack trace exposure", re.compile(r"(?i)(traceback\.format|print_exc|format_exc)")),
    ("Debug mode enabled", re.compile(r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True|app\.debug)")),
    ("Verbose error messages", re.compile(r"(?i)(return.*str\(e\)|return.*str\(exc\)|return.*exception)")),
    ("Database error exposure", re.compile(r"(?i)(sqlalchemy.*error|database.*error|sql.*exception)")),
    ("Internal path disclosure", re.compile(r"(?i)(os\.path|__file__|sys\.path|abspath)")),
]


class OutputAgent(BaseAgent):
    """Analyse output handling for sanitization, PII leakage, and information disclosure."""

    name: ClassVar[str] = "output"
    description: ClassVar[str] = (
        "Checks AI agent outputs for HTML/JS injection, PII leakage, "
        "error message information disclosure, and rate limiting."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM05", "ASI09"]
    depends_on: ClassVar[list[str]] = ["dataflow"]

    async def analyze(self) -> None:
        """Run all output security checks."""
        source_files = await self._collect_source_files()
        if not source_files:
            logger.warning("No source files collected; skipping output analysis")
            return

        await self._check_output_sanitization(source_files)
        await self._check_pii_leakage(source_files)
        await self._check_error_disclosure(source_files)
        await self._check_rate_limiting(source_files)

    # ------------------------------------------------------------------
    # Source file collection
    # ------------------------------------------------------------------

    async def _collect_source_files(self) -> dict[str, str]:
        """Gather source files from the container."""
        cid = self.context.container_id
        if not cid:
            return {}

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /app /src /opt -maxdepth 5 -type f "
                "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' "
                "-o -name '*.html' -o -name '*.jinja' -o -name '*.jinja2' "
                "-o -name '*.hbs' -o -name '*.ejs' \\) "
                "-size -512k 2>/dev/null | head -100",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            file_list = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return {}

        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "65536", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    contents[fpath] = stdout.decode(errors="replace")
            except Exception:
                continue
        return contents

    # ------------------------------------------------------------------
    # Output sanitization check
    # ------------------------------------------------------------------

    async def _check_output_sanitization(self, source_files: dict[str, str]) -> None:
        """Check whether output sanitization is implemented."""
        # Look for template rendering without auto-escaping
        template_files: list[str] = []
        unsanitized_outputs: list[tuple[str, str]] = []
        sanitized_files: list[str] = []

        for fpath, content in source_files.items():
            # Check for template files that might render unsanitized content
            if any(fpath.endswith(ext) for ext in (".html", ".jinja", ".jinja2", ".hbs", ".ejs")):
                template_files.append(fpath)
                # Check for raw/unescaped output markers
                if re.search(r"\{\{!|{%\s*raw\s*%}|<%[-=]|{{{\s*\w+\s*}}}", content):
                    unsanitized_outputs.append((fpath, "Unescaped template output"))

            # Check for sanitization in Python/JS source
            for pattern in SANITIZATION_PATTERNS:
                if pattern.search(content):
                    sanitized_files.append(fpath)
                    break

            # Check for injection-prone output patterns
            for pattern_name, regex, desc in OUTPUT_INJECTION_PATTERNS:
                matches = regex.findall(content)
                if matches:
                    # Skip if it's in a test file
                    if "test" not in fpath.lower():
                        unsanitized_outputs.append((fpath, pattern_name))

        if not sanitized_files and source_files:
            self.add_finding(
                title="No output sanitization detected",
                description=(
                    "No output sanitization, HTML escaping, or Content Security "
                    "Policy (CSP) mechanisms were found in the agent's source code. "
                    "Without output sanitization, the AI agent's responses could be "
                    "used to inject malicious HTML, JavaScript, or other client-side "
                    "code, leading to cross-site scripting (XSS) attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No sanitization patterns found",
                        raw_data=f"Searched {len(source_files)} files for sanitization patterns",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement output sanitization for all AI agent responses. "
                    "Use HTML escaping (html.escape in Python, DOMPurify in JS) "
                    "before rendering agent output in web interfaces. Set a strict "
                    "Content Security Policy (CSP) header. Enable auto-escaping in "
                    "template engines (Jinja2 autoescape=True)."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=7.0,
                ai_risk_score=7.5,
            )
        elif unsanitized_outputs:
            details = "\n".join(
                f"  {fpath}: {issue}" for fpath, issue in unsanitized_outputs[:15]
            )
            self.add_finding(
                title=f"Potentially unsanitized output paths ({len(unsanitized_outputs)})",
                description=(
                    f"Found {len(unsanitized_outputs)} potential unsanitized output "
                    "path(s) in the agent's code. While some sanitization mechanisms "
                    f"exist ({len(sanitized_files)} files), these output paths may "
                    "bypass them."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Unsanitized output paths",
                        raw_data=details,
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Ensure all output paths are covered by sanitization. "
                    "Review template files for unescaped output markers. "
                    "Apply defense-in-depth with CSP headers."
                ),
                cvss_score=5.5,
                ai_risk_score=6.0,
            )
        else:
            self.add_finding(
                title="Output sanitization mechanisms detected",
                description=(
                    f"Output sanitization was found in {len(sanitized_files)} "
                    "file(s). Verify that sanitization is applied consistently "
                    "to all output paths."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM05"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Sanitization in {len(sanitized_files)} files",
                        raw_data="\n".join(f"  {f}" for f in sanitized_files[:20]),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation="Continue verifying sanitization coverage across all output paths.",
            )

    # ------------------------------------------------------------------
    # PII leakage in outputs
    # ------------------------------------------------------------------

    async def _check_pii_leakage(self, source_files: dict[str, str]) -> None:
        """Check for PII that might leak through agent outputs."""
        # Use dataflow findings to understand the PII landscape
        dataflow_result = self.context.agent_results.get("dataflow")
        has_pii_in_data = False
        if dataflow_result:
            has_pii_in_data = any("PII" in f.title for f in dataflow_result.findings)

        # Check if there's PII filtering/redaction in output handlers
        pii_filter_patterns = [
            re.compile(r"(?i)(redact|mask|anonymize|pseudonymize|pii.filter|pii.remov)"),
            re.compile(r"(?i)(data.loss.prevention|dlp|sensitive.data.filter)"),
            re.compile(r"(?i)(scrub|sanitize.pii|remove.pii|filter.personal)"),
        ]

        has_pii_filtering = False
        for fpath, content in source_files.items():
            for pattern in pii_filter_patterns:
                if pattern.search(content):
                    has_pii_filtering = True
                    break
            if has_pii_filtering:
                break

        # Check response/output handling for PII patterns
        output_handler_files: list[str] = []
        for fpath, content in source_files.items():
            if re.search(r"(?i)(response|output|reply|answer|result|send)", fpath.lower()):
                output_handler_files.append(fpath)
            elif re.search(r"(?i)(return.*response|send.*message|reply|output.*result)", content):
                output_handler_files.append(fpath)

        if has_pii_in_data and not has_pii_filtering:
            self.add_finding(
                title="PII detected without output-level filtering",
                description=(
                    "PII data was detected in the container (from dataflow analysis) "
                    "but no PII filtering, redaction, or masking mechanisms were "
                    "found in the output handling code. The AI agent may "
                    "inadvertently include PII in its responses."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No PII filtering in outputs",
                        raw_data=(
                            f"PII found in data: Yes\n"
                            f"PII output filtering: No\n"
                            f"Output handler files: {len(output_handler_files)}"
                        ),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement PII redaction in the agent's output pipeline. "
                    "Use regex-based filtering, NER-based PII detection, or "
                    "a data loss prevention (DLP) solution to automatically "
                    "mask PII before it reaches end users. Consider using "
                    "Microsoft Presidio or similar PII detection libraries."
                ),
                references=[
                    "https://microsoft.github.io/presidio/",
                ],
                cvss_score=6.5,
                ai_risk_score=7.0,
            )
        elif has_pii_in_data and has_pii_filtering:
            self.add_finding(
                title="PII filtering mechanisms present",
                description=(
                    "PII data exists in the container and PII filtering "
                    "mechanisms were detected. Verify that filtering is applied "
                    "to all output channels and covers all PII types."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM05"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="PII filtering detected",
                        raw_data="PII filtering patterns found in source code",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation="Verify PII filtering coverage across all output channels.",
            )

    # ------------------------------------------------------------------
    # Error information disclosure
    # ------------------------------------------------------------------

    async def _check_error_disclosure(self, source_files: dict[str, str]) -> None:
        """Check for error message information disclosure."""
        disclosure_hits: list[tuple[str, str, str]] = []  # (pattern_name, file, snippet)

        for fpath, content in source_files.items():
            for pattern_name, regex in ERROR_DISCLOSURE_PATTERNS:
                matches = list(regex.finditer(content))
                for m in matches[:3]:
                    start = max(0, m.start() - 40)
                    end = min(len(content), m.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    disclosure_hits.append((pattern_name, fpath, snippet))

        if not disclosure_hits:
            return

        # Distinguish debug mode (critical) from other disclosures
        has_debug = any(name == "Debug mode enabled" for name, _, _ in disclosure_hits)

        details = "\n".join(
            f"  [{name}] {fpath}: {snippet[:100]}"
            for name, fpath, snippet in disclosure_hits[:20]
        )

        severity = Severity.HIGH if has_debug else Severity.MEDIUM

        self.add_finding(
            title=f"Error information disclosure risks ({len(disclosure_hits)} patterns)",
            description=(
                f"Found {len(disclosure_hits)} pattern(s) that may disclose "
                "sensitive information through error messages."
                + (" Debug mode appears to be enabled, which typically exposes "
                   "stack traces, internal paths, and configuration to end users."
                   if has_debug else "")
                + " Error message disclosure can reveal internal architecture, "
                "file paths, database schemas, and other information useful "
                "for targeted attacks."
            ),
            severity=severity,
            owasp_llm=["LLM05"],
            owasp_agentic=["ASI09"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Error disclosure patterns ({len(disclosure_hits)} matches)",
                    raw_data=details,
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Disable debug mode in production. Implement custom error "
                "handlers that return generic error messages to users while "
                "logging detailed errors internally. Never expose stack traces, "
                "database errors, or file paths in API responses."
            ),
            cvss_score=5.5 if has_debug else 4.0,
            ai_risk_score=5.0,
        )

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _check_rate_limiting(self, source_files: dict[str, str]) -> None:
        """Check for rate limiting on agent endpoints."""
        rate_limit_patterns = [
            re.compile(r"(?i)(rate.?limit|throttl|slowapi|limiter|RateLimiter)"),
            re.compile(r"(?i)(requests?.per.?(second|minute|hour)|max.?requests)"),
            re.compile(r"(?i)(429|too.?many.?requests|rate.?exceeded)"),
            re.compile(r"(?i)(token.?bucket|leaky.?bucket|sliding.?window)"),
        ]

        has_rate_limiting = False
        rate_limit_files: list[str] = []

        for fpath, content in source_files.items():
            for pattern in rate_limit_patterns:
                if pattern.search(content):
                    has_rate_limiting = True
                    rate_limit_files.append(fpath)
                    break

        # Also check for rate limiting in nginx/caddy/reverse proxy configs
        cid = self.context.container_id
        if cid and not has_rate_limiting:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid,
                    "sh", "-c",
                    "find / -maxdepth 4 "
                    "\\( -name 'nginx.conf' -o -name 'Caddyfile' -o -name 'haproxy.cfg' \\) "
                    "2>/dev/null | head -5",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                proxy_files = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
                if proxy_files:
                    for pf in proxy_files.splitlines():
                        pf = pf.strip()
                        if not pf:
                            continue
                        try:
                            proc2 = await asyncio.create_subprocess_exec(
                                "docker", "exec", cid, "cat", pf,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            stdout2, _ = await proc2.communicate()
                            if proc2.returncode == 0:
                                proxy_content = stdout2.decode(errors="replace")
                                if re.search(r"(?i)(limit_req|rate_limit|limit_conn)", proxy_content):
                                    has_rate_limiting = True
                                    rate_limit_files.append(pf)
                        except Exception:
                            continue
            except Exception:
                pass

        if not has_rate_limiting:
            self.add_finding(
                title="No rate limiting detected on agent endpoints",
                description=(
                    "No rate limiting mechanisms were found in the agent's "
                    "source code or reverse proxy configuration. Without rate "
                    "limiting, the AI agent is vulnerable to: denial-of-service "
                    "attacks, brute-force prompt injection attempts, resource "
                    "exhaustion (unbounded LLM API calls), and automated abuse."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No rate limiting found",
                        raw_data=f"Searched {len(source_files)} files and proxy configs",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement rate limiting at the application level (e.g., "
                    "SlowAPI for FastAPI, express-rate-limit for Express) or "
                    "at the reverse proxy level (nginx limit_req). Set appropriate "
                    "limits for: requests per IP, requests per authenticated user, "
                    "and total API calls per time window."
                ),
                cvss_score=4.5,
                ai_risk_score=5.0,
            )
        else:
            self.add_finding(
                title="Rate limiting mechanisms detected",
                description=(
                    f"Rate limiting was found in {len(rate_limit_files)} file(s). "
                    "Verify that rate limits are applied to all public endpoints "
                    "and are set at appropriate thresholds."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM05"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Rate limiting in {len(rate_limit_files)} files",
                        raw_data="\n".join(f"  {f}" for f in rate_limit_files[:10]),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation="Verify rate limits are appropriate for production workloads.",
            )
