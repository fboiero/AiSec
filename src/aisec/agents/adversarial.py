"""Adversarial testing agent -- evasion, encoding bypass, fuzzing, and manipulation."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dangerous code execution patterns
# ---------------------------------------------------------------------------
DANGEROUS_CODE_PATTERNS: list[tuple[re.Pattern[str], str, Severity, str]] = [
    (
        re.compile(r"(?<!def )\beval\s*\("),
        "eval()",
        Severity.CRITICAL,
        "Replace eval() with ast.literal_eval() or a safe expression parser.",
    ),
    (
        re.compile(r"(?<!def )\bexec\s*\("),
        "exec()",
        Severity.CRITICAL,
        "Remove exec() and use explicit logic or a sandboxed execution environment.",
    ),
    (
        re.compile(r"\bcompile\s*\(.*['\"]exec['\"]"),
        "compile()",
        Severity.HIGH,
        "Avoid compile() with exec mode on untrusted input.",
    ),
    (
        re.compile(r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        "subprocess with shell=True",
        Severity.HIGH,
        "Use subprocess with shell=False and pass arguments as a list.",
    ),
    (
        re.compile(r"os\.system\s*\("),
        "os.system()",
        Severity.HIGH,
        "Replace os.system() with subprocess.run() using shell=False.",
    ),
    (
        re.compile(r"os\.popen\s*\("),
        "os.popen()",
        Severity.HIGH,
        "Replace os.popen() with subprocess.run() using shell=False.",
    ),
    (
        re.compile(r"\b(?:importlib\.import_module|__import__)\s*\("),
        "Dynamic import",
        Severity.MEDIUM,
        "Validate module names against an allow-list before dynamic imports.",
    ),
    (
        re.compile(r"(?i)(?:Environment|Template)\s*\(.*from_string|from_string\s*\("),
        "Jinja2 from_string / template injection",
        Severity.HIGH,
        "Use sandboxed Jinja2 environments and avoid rendering user-controlled templates.",
    ),
    (
        re.compile(r"f['\"].*\{.*\}.*['\"].*\.render|\.render\s*\(.*f['\"]"),
        "f-string in template rendering",
        Severity.MEDIUM,
        "Do not use f-strings to build template content; pass variables through the template context.",
    ),
]

# ---------------------------------------------------------------------------
# Sandbox escape indicators (checked in container inspect JSON)
# ---------------------------------------------------------------------------
SANDBOX_ESCAPE_INDICATORS: list[tuple[str, str, Severity, str]] = [
    (
        "/var/run/docker.sock",
        "Docker socket mounted",
        Severity.CRITICAL,
        "Remove the Docker socket mount. Use a restricted Docker API proxy if container management is required.",
    ),
    (
        "Privileged",
        "Privileged mode enabled",
        Severity.CRITICAL,
        "Remove --privileged flag and use --cap-drop ALL with selective --cap-add.",
    ),
    (
        "SYS_ADMIN",
        "SYS_ADMIN capability granted",
        Severity.CRITICAL,
        "Drop SYS_ADMIN capability. It is effectively root-equivalent.",
    ),
    (
        "NET_ADMIN",
        "NET_ADMIN capability granted",
        Severity.HIGH,
        "Drop NET_ADMIN unless the agent genuinely needs network configuration access.",
    ),
    (
        "SYS_PTRACE",
        "SYS_PTRACE capability granted",
        Severity.HIGH,
        "Drop SYS_PTRACE. It enables process tracing and memory inspection.",
    ),
    (
        "PidMode",
        "Host PID namespace shared",
        Severity.CRITICAL,
        "Remove --pid=host. Use isolated PID namespaces.",
    ),
    (
        "NetworkMode:host",
        "Host network namespace shared",
        Severity.HIGH,
        "Remove --network=host. Use bridge or overlay networks.",
    ),
    (
        "seccomp=unconfined",
        "Seccomp profile disabled",
        Severity.HIGH,
        "Remove --security-opt seccomp=unconfined. Use the default or a custom seccomp profile.",
    ),
]

# ---------------------------------------------------------------------------
# Encoding bypass patterns
# ---------------------------------------------------------------------------
ENCODING_BYPASS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bbase64\.(b64decode|decodebytes|decodestring)\s*\("), "Base64 decode"),
    (re.compile(r"(?i)\bbytes\.fromhex\s*\("), "Hex decode"),
    (re.compile(r"(?i)\bcodecs\.decode\s*\("), "Codecs decode"),
    (re.compile(r"(?i)\burllib\.parse\.(unquote|unquote_plus)\s*\("), "URL decode"),
    (re.compile(r"(?i)\b(?:unicodedata\.normalize|NFKC|NFKD|NFC|NFD)\b"), "Unicode normalization"),
    (re.compile(r"(?i)\\u200[bcdef]|\\ufeff|\\u00ad|\\u2060"), "Invisible Unicode characters"),
    (re.compile(r"(?i)utf[\-_]?7|utf[\-_]?16[\-_]?bom|chardet|charset"), "Character set handling"),
    (re.compile(r"(?i)%25[0-9a-fA-F]{2}|%(?:25)+"), "Double URL encoding"),
    (re.compile(r"(?i)\bhomoglyph|confusable|look[\-_]?alike"), "Homoglyph handling"),
]


class AdversarialAgent(BaseAgent):
    """Active adversarial testing for evasion attacks, encoding bypass,
    input fuzzing, sandbox escape detection, and multi-turn manipulation analysis."""

    name: ClassVar[str] = "adversarial"
    description: ClassVar[str] = (
        "Active adversarial testing for evasion attacks, encoding bypass, "
        "input fuzzing, sandbox escape detection, and multi-turn manipulation analysis."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM05", "LLM06", "ASI01", "ASI02", "ASI05"]
    depends_on: ClassVar[list[str]] = ["permission", "prompt_security"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all adversarial testing checks."""
        container_info = await self._get_container_info()
        source_files = await self._collect_source_files()

        await self._check_code_execution_surface(source_files)
        await self._check_sandbox_escape(container_info)
        await self._check_encoding_bypass(source_files)
        await self._check_input_fuzzing_surface(source_files)
        await self._check_resource_exhaustion(container_info, source_files)
        await self._check_multi_turn_manipulation(source_files)
        await self._check_tool_injection(source_files)

    # ------------------------------------------------------------------
    # Container / file helpers
    # ------------------------------------------------------------------

    async def _get_container_info(self) -> dict[str, Any]:
        """Retrieve container inspect data."""
        cid = self.context.container_id
        if not cid:
            return {}
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            data = json.loads(stdout.decode(errors="replace"))
            return data[0] if isinstance(data, list) else data
        except Exception:
            return {}

    async def _exec_in_container(self, command: str) -> str:
        """Run a shell command inside the target container and return stdout."""
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    async def _collect_source_files(self) -> dict[str, str]:
        """Gather source code from the container."""
        cid = self.context.container_id
        if not cid:
            return {}
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /app /src /opt -maxdepth 5 -type f "
                "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' "
                "-o -name '*.yaml' -o -name '*.yml' -o -name '*.json' "
                "-o -name '*.toml' \\) -size -512k 2>/dev/null | head -100",
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
    # 1. Code execution surface
    # ------------------------------------------------------------------

    async def _check_code_execution_surface(self, source_files: dict[str, str]) -> None:
        """Find dangerous code execution patterns in source files."""
        hits: list[tuple[str, str, Severity, str, str]] = []

        for fpath, content in source_files.items():
            for pattern, name, severity, remediation in DANGEROUS_CODE_PATTERNS:
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    hits.append((name, fpath, severity, remediation, snippet))

        if not hits:
            return

        critical_hits = [h for h in hits if h[2] == Severity.CRITICAL]
        high_hits = [h for h in hits if h[2] == Severity.HIGH]
        other_hits = [h for h in hits if h[2] not in (Severity.CRITICAL, Severity.HIGH)]

        worst_severity = Severity.CRITICAL if critical_hits else (
            Severity.HIGH if high_hits else Severity.MEDIUM
        )

        details = "\n".join(
            f"  [{sev.value.upper()}] {name} in {fpath}: {snippet[:100]}"
            for name, fpath, sev, _, snippet in hits[:25]
        )

        unique_remediations: list[str] = []
        seen_names: set[str] = set()
        for name, _, _, remediation, _ in hits:
            if name not in seen_names:
                unique_remediations.append(f"  - {name}: {remediation}")
                seen_names.add(name)

        self.add_finding(
            title=f"Dangerous code execution surface ({len(hits)} patterns)",
            description=(
                f"Found {len(hits)} dangerous code execution pattern(s) across the "
                f"source code: {len(critical_hits)} critical, {len(high_hits)} high, "
                f"{len(other_hits)} medium/low. These patterns create attack surface "
                "for adversarial code injection. An attacker who can influence input "
                "to eval(), exec(), shell commands, or template rendering can achieve "
                "arbitrary code execution within the container."
            ),
            severity=worst_severity,
            owasp_llm=["LLM01", "LLM05"],
            owasp_agentic=["ASI05", "ASI02"],
            nist_ai_rmf=["MEASURE", "MANAGE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Code execution patterns ({len(hits)} matches)",
                    raw_data=details,
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation="\n".join(unique_remediations),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=9.8 if worst_severity == Severity.CRITICAL else 7.5,
            ai_risk_score=9.0,
        )

    # ------------------------------------------------------------------
    # 2. Sandbox escape detection
    # ------------------------------------------------------------------

    async def _check_sandbox_escape(self, info: dict[str, Any]) -> None:
        """Detect potential sandbox escape vectors from container configuration."""
        cid = self.context.container_id
        if not cid or not info:
            return

        host_config = info.get("HostConfig", {})
        mounts = info.get("Mounts", [])
        config_str = json.dumps(info, default=str)

        issues: list[tuple[str, Severity, str]] = []

        # Check Docker socket mount
        for mount in mounts:
            source = mount.get("Source", "")
            if "docker.sock" in source:
                issues.append((
                    f"Docker socket mounted from {source}",
                    Severity.CRITICAL,
                    "Remove the Docker socket mount. Use a restricted API proxy if needed.",
                ))

        # Check privileged mode
        if host_config.get("Privileged", False):
            issues.append((
                "Container running in privileged mode",
                Severity.CRITICAL,
                "Remove --privileged and use --cap-drop ALL with selective --cap-add.",
            ))

        # Check dangerous capabilities
        cap_add: list[str] = host_config.get("CapAdd") or []
        for cap in cap_add:
            cap_upper = cap.upper()
            if cap_upper in ("SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO"):
                issues.append((
                    f"Dangerous capability {cap_upper} granted",
                    Severity.CRITICAL,
                    f"Drop {cap_upper} capability. It enables container escape.",
                ))
            elif cap_upper in ("NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"):
                issues.append((
                    f"Elevated capability {cap_upper} granted",
                    Severity.HIGH,
                    f"Drop {cap_upper} unless strictly required.",
                ))

        # Check host PID namespace
        pid_mode = host_config.get("PidMode", "")
        if pid_mode == "host":
            issues.append((
                "Host PID namespace shared (--pid=host)",
                Severity.CRITICAL,
                "Remove --pid=host to isolate process namespaces.",
            ))

        # Check host network namespace
        network_mode = host_config.get("NetworkMode", "")
        if network_mode == "host":
            issues.append((
                "Host network namespace shared (--network=host)",
                Severity.HIGH,
                "Use bridge or overlay networking instead of host mode.",
            ))

        # Check sensitive host path mounts
        sensitive_host_paths = ("/etc", "/root", "/home", "/var/run", "/proc", "/sys")
        for mount in mounts:
            source = mount.get("Source", "")
            dest = mount.get("Destination", "")
            if any(source.startswith(p) for p in sensitive_host_paths):
                if "docker.sock" not in source:  # Already flagged above
                    rw = not mount.get("RW", True) is False
                    mode = "read-write" if rw else "read-only"
                    issues.append((
                        f"Sensitive host path mounted: {source} -> {dest} ({mode})",
                        Severity.HIGH,
                        f"Remove mount of {source} or restrict to read-only with minimal scope.",
                    ))

        # Check seccomp profile
        security_opts: list[str] = host_config.get("SecurityOpt") or []
        for opt in security_opts:
            if "seccomp=unconfined" in opt:
                issues.append((
                    "Seccomp profile disabled (seccomp=unconfined)",
                    Severity.HIGH,
                    "Use the default seccomp profile or a custom restrictive profile.",
                ))

        # Check for escape tools inside the container
        escape_tools = await self._exec_in_container(
            "which nsenter cgroups-escape runc 2>/dev/null; "
            "ls /usr/bin/nsenter /usr/sbin/nsenter 2>/dev/null"
        )
        if escape_tools:
            issues.append((
                f"Container escape tools found: {escape_tools.replace(chr(10), ', ')}",
                Severity.HIGH,
                "Remove nsenter, runc, and other escape-capable binaries from the container image.",
            ))

        if not issues:
            return

        worst_severity = Severity.CRITICAL if any(
            s == Severity.CRITICAL for _, s, _ in issues
        ) else Severity.HIGH

        details = "\n".join(
            f"  [{sev.value.upper()}] {desc}" for desc, sev, _ in issues
        )
        remediation_lines = "\n".join(
            f"  - {rem}" for _, _, rem in issues
        )

        self.add_finding(
            title=f"Sandbox escape vectors detected ({len(issues)} issues)",
            description=(
                f"Found {len(issues)} container configuration issue(s) that could "
                "enable sandbox escape. An adversary who gains code execution inside "
                "the container could leverage these misconfigurations to escape the "
                "container boundary and compromise the host system."
            ),
            severity=worst_severity,
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI05", "ASI02"],
            nist_ai_rmf=["GOVERN", "MANAGE"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"Sandbox escape vectors ({len(issues)} issues)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=remediation_lines,
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
            ],
            cvss_score=9.8 if worst_severity == Severity.CRITICAL else 7.5,
            ai_risk_score=9.5,
        )

    # ------------------------------------------------------------------
    # 3. Encoding bypass analysis
    # ------------------------------------------------------------------

    async def _check_encoding_bypass(self, source_files: dict[str, str]) -> None:
        """Analyse input handling for encoding bypass risks."""
        hits: list[tuple[str, str, str]] = []  # (pattern_name, file, snippet)

        for fpath, content in source_files.items():
            for pattern, name in ENCODING_BYPASS_PATTERNS:
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    hits.append((name, fpath, snippet))

        if not hits:
            return

        # Check whether there is validation after decode operations
        has_post_decode_validation = False
        for fpath, content in source_files.items():
            if re.search(
                r"(?i)(decode|unquote|fromhex|b64decode).*\n.*"
                r"(validate|sanitize|filter|check|verify|strip|replace)",
                content,
            ):
                has_post_decode_validation = True
                break

        severity = Severity.MEDIUM if has_post_decode_validation else Severity.HIGH

        details = "\n".join(
            f"  [{name}] {fpath}: {snippet[:100]}"
            for name, fpath, snippet in hits[:25]
        )

        # Categorize by risk type
        decode_hits = [h for h in hits if "decode" in h[0].lower()]
        unicode_hits = [h for h in hits if "unicode" in h[0].lower() or "homoglyph" in h[0].lower()]
        charset_hits = [h for h in hits if "character" in h[0].lower() or "charset" in h[0].lower()]
        double_enc_hits = [h for h in hits if "double" in h[0].lower()]

        category_summary = ", ".join(filter(None, [
            f"{len(decode_hits)} decode operations" if decode_hits else "",
            f"{len(unicode_hits)} Unicode handling" if unicode_hits else "",
            f"{len(charset_hits)} charset handling" if charset_hits else "",
            f"{len(double_enc_hits)} double encoding" if double_enc_hits else "",
        ]))

        self.add_finding(
            title=f"Encoding bypass risk ({len(hits)} patterns)",
            description=(
                f"Found {len(hits)} encoding/decoding pattern(s) that could be "
                f"exploited for filter bypass: {category_summary}. "
                "Attackers can encode malicious payloads using base64, hex, URL "
                "encoding, Unicode normalization, or double encoding to evade "
                "input validation and security filters."
                + (
                    " Post-decode validation was detected, which reduces the risk."
                    if has_post_decode_validation else
                    " No post-decode validation was detected, increasing the risk "
                    "of encoded payloads reaching sensitive operations."
                )
            ),
            severity=severity,
            owasp_llm=["LLM01", "LLM05"],
            owasp_agentic=["ASI01"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Encoding bypass patterns ({len(hits)} matches)",
                    raw_data=details,
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Apply validation AFTER decoding, not before. Normalize all input "
                "to a canonical form (e.g., NFC) before applying security checks. "
                "Reject double-encoded input. Use allow-lists rather than deny-lists "
                "for input validation. Apply consistent encoding throughout the "
                "processing pipeline."
            ),
            references=[
                "https://owasp.org/www-community/Double_Encoding",
                "https://unicode.org/reports/tr36/",
            ],
            cvss_score=6.5 if has_post_decode_validation else 7.5,
            ai_risk_score=7.0,
        )

    # ------------------------------------------------------------------
    # 4. Input fuzzing surface
    # ------------------------------------------------------------------

    async def _check_input_fuzzing_surface(self, source_files: dict[str, str]) -> None:
        """Identify potential fuzzing targets based on input surface analysis."""
        cid = self.context.container_id
        targets: list[tuple[str, str, str]] = []  # (category, file, snippet)

        api_patterns = [
            (re.compile(r"@(?:app|router)\.\s*(?:get|post|put|delete|patch|route)\s*\("), "API endpoint"),
            (re.compile(r"(?i)(?:FastAPI|Flask|Django|Express|Koa)\s*\("), "Web framework"),
            (re.compile(r"(?i)request\.\s*(?:json|form|data|args|params|body|files)"), "Request data access"),
        ]

        upload_patterns = [
            (re.compile(r"(?i)(?:upload|file|multipart|form[\-_]?data)"), "File upload handler"),
            (re.compile(r"(?i)(?:UploadFile|FileStorage|multer|formidable)"), "Upload library"),
        ]

        argparse_patterns = [
            (re.compile(r"(?:argparse|click|typer|fire)\b"), "CLI argument parser"),
            (re.compile(r"(?:sys\.argv|getopt)\b"), "Raw argument access"),
        ]

        env_patterns = [
            (re.compile(r"os\.environ\s*(?:\[|\.get\s*\()"), "Environment variable"),
            (re.compile(r"(?i)(?:getenv|env\[|process\.env)"), "Environment access"),
        ]

        config_patterns = [
            (re.compile(r"(?i)yaml\.(?:safe_)?load\s*\("), "YAML deserialization"),
            (re.compile(r"(?i)json\.loads?\s*\("), "JSON deserialization"),
            (re.compile(r"(?i)toml\.loads?\s*\("), "TOML deserialization"),
            (re.compile(r"(?i)pickle\.loads?\s*\("), "Pickle deserialization"),
            (re.compile(r"(?i)marshal\.loads?\s*\("), "Marshal deserialization"),
        ]

        all_pattern_groups = [
            ("API endpoints", api_patterns),
            ("File uploads", upload_patterns),
            ("CLI arguments", argparse_patterns),
            ("Environment variables", env_patterns),
            ("Config deserialization", config_patterns),
        ]

        for fpath, content in source_files.items():
            for category, patterns in all_pattern_groups:
                for pattern, label in patterns:
                    for match in pattern.finditer(content):
                        start = max(0, match.start() - 20)
                        end = min(len(content), match.end() + 60)
                        snippet = content[start:end].strip().replace("\n", " ")
                        targets.append((f"{category}: {label}", fpath, snippet))

        if not targets:
            return

        # Check for unsafe deserialization specifically
        unsafe_deser = [
            t for t in targets
            if "pickle" in t[0].lower() or "marshal" in t[0].lower()
        ]

        # Determine severity based on exposure
        has_api = any("API" in t[0] for t in targets)
        has_upload = any("upload" in t[0].lower() for t in targets)
        has_unsafe_deser = len(unsafe_deser) > 0

        if has_unsafe_deser:
            severity = Severity.CRITICAL
        elif has_api and has_upload:
            severity = Severity.HIGH
        elif has_api:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Group by category
        categories: dict[str, int] = {}
        for cat, _, _ in targets:
            base_cat = cat.split(":")[0]
            categories[base_cat] = categories.get(base_cat, 0) + 1

        category_summary = ", ".join(f"{cat} ({cnt})" for cat, cnt in categories.items())

        details = "\n".join(
            f"  [{cat}] {fpath}: {snippet[:100]}"
            for cat, fpath, snippet in targets[:30]
        )

        self.add_finding(
            title=f"Input fuzzing surface ({len(targets)} entry points)",
            description=(
                f"Identified {len(targets)} potential input entry point(s) across "
                f"the application: {category_summary}. These entry points accept "
                "external input and represent the attack surface for adversarial "
                "fuzzing. Each entry point should validate, sanitize, and bound "
                "its input to prevent injection, overflow, and deserialization attacks."
                + (
                    " CRITICAL: Unsafe deserialization (pickle/marshal) was detected, "
                    "which allows arbitrary code execution from crafted input."
                    if has_unsafe_deser else ""
                )
            ),
            severity=severity,
            owasp_llm=["LLM01", "LLM05"],
            owasp_agentic=["ASI01", "ASI05"],
            nist_ai_rmf=["MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Input surface ({len(targets)} entry points)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Validate and sanitize all external inputs at each entry point. "
                "Use schema validation for API inputs. Limit upload file types and sizes. "
                "Replace pickle/marshal with JSON or MessagePack for deserialization. "
                "Use yaml.safe_load() instead of yaml.load(). Implement request "
                "size limits and content-type enforcement."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            cvss_score=9.0 if has_unsafe_deser else (6.5 if has_api else 4.0),
            ai_risk_score=7.5,
        )

    # ------------------------------------------------------------------
    # 5. Resource exhaustion
    # ------------------------------------------------------------------

    async def _check_resource_exhaustion(
        self,
        info: dict[str, Any],
        source_files: dict[str, str],
    ) -> None:
        """Check for resource consumption risks that enable denial-of-service."""
        cid = self.context.container_id
        issues: list[tuple[str, Severity]] = []

        # Container resource limits
        if info:
            host_config = info.get("HostConfig", {})

            memory_limit = host_config.get("Memory", 0)
            if not memory_limit:
                issues.append(("No container memory limit set", Severity.MEDIUM))

            cpu_quota = host_config.get("CpuQuota", 0)
            cpu_period = host_config.get("CpuPeriod", 0)
            nano_cpus = host_config.get("NanoCpus", 0)
            if not cpu_quota and not nano_cpus:
                issues.append(("No container CPU limit set", Severity.MEDIUM))

            pids_limit = host_config.get("PidsLimit", 0)
            if not pids_limit or pids_limit < 0:
                issues.append(("No container PID limit set", Severity.LOW))

        # Source code checks for missing safeguards
        for fpath, content in source_files.items():
            # Recursive operations without depth limits
            if re.search(r"def\s+(\w+)\s*\([^)]*\).*\n(?:.*\n)*?.*\1\s*\(", content):
                issues.append((f"Recursive function without apparent depth limit in {fpath}", Severity.MEDIUM))
            elif re.search(r"(?i)recurs|while\s+True|for\s+.*\s+in\s+.*itertools\.count", content):
                if not re.search(r"(?i)max_depth|max_recurs|depth_limit|recursion_limit", content):
                    issues.append((f"Unbounded iteration or recursion pattern in {fpath}", Severity.MEDIUM))

            # Missing timeouts on external calls
            if re.search(r"requests\.(get|post|put|delete|patch|head)\s*\(", content):
                if not re.search(r"timeout\s*=", content):
                    issues.append((f"HTTP requests without timeout in {fpath}", Severity.MEDIUM))

            if re.search(r"(?:aiohttp|httpx)\.\s*(?:get|post|request)", content):
                if not re.search(r"timeout\s*=", content):
                    issues.append((f"Async HTTP requests without timeout in {fpath}", Severity.MEDIUM))

            # Missing request size limits
            if re.search(r"(?i)(?:MAX_CONTENT_LENGTH|max_request_size|body_limit|limit.*size)", content):
                pass  # Has size limits
            elif re.search(r"request\.\s*(?:json|data|body|get_json)", content):
                issues.append((f"Request body consumed without size limit in {fpath}", Severity.MEDIUM))

            # Missing rate limiting
            if re.search(r"@(?:app|router)\.\s*(?:get|post|put|delete|patch|route)\s*\(", content):
                if not re.search(r"(?i)(?:rate.?limit|throttl|slowapi|limiter|RateLimit)", content):
                    issues.append((f"API endpoint without rate limiting in {fpath}", Severity.MEDIUM))
                    break  # One finding is enough for rate limiting

        if not issues:
            return

        severity = max(
            (s for _, s in issues),
            key=lambda s: list(Severity).index(s),
        )

        details = "\n".join(
            f"  [{sev.value.upper()}] {desc}" for desc, sev in issues[:25]
        )

        self.add_finding(
            title=f"Resource exhaustion risks ({len(issues)} issues)",
            description=(
                f"Found {len(issues)} resource exhaustion risk(s). Missing resource "
                "limits allow an adversary to perform denial-of-service attacks by "
                "exhausting memory, CPU, file descriptors, or request quotas. Without "
                "proper bounds, a single malicious request or prompt can render the "
                "service unavailable."
            ),
            severity=severity,
            owasp_llm=["LLM05"],
            owasp_agentic=["ASI01", "ASI05"],
            nist_ai_rmf=["MEASURE", "MANAGE"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"Resource exhaustion risks ({len(issues)} issues)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=(
                "Set container memory limits (--memory), CPU limits (--cpus), and "
                "PID limits (--pids-limit). Add timeouts to all external HTTP calls. "
                "Implement request size limits in the web framework. Add rate limiting "
                "to all API endpoints. Set recursion/depth limits for recursive "
                "operations. Use asyncio.wait_for() for async operations."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=6.0,
            ai_risk_score=5.5,
        )

    # ------------------------------------------------------------------
    # 6. Multi-turn manipulation
    # ------------------------------------------------------------------

    async def _check_multi_turn_manipulation(self, source_files: dict[str, str]) -> None:
        """Analyse conversation and session management for manipulation risks."""
        cid = self.context.container_id
        issues: list[tuple[str, Severity, str]] = []

        # Check for session / conversation state storage
        session_patterns = [
            re.compile(r"(?i)(?:session|conversation|chat)[\-_]?(?:store|storage|history|log|memory|state)"),
            re.compile(r"(?i)(?:message|turn)[\-_]?(?:history|buffer|log)"),
            re.compile(r"(?i)(?:ConversationBuffer|ConversationSummary|ChatMessageHistory)"),
        ]

        memory_patterns = [
            re.compile(r"(?i)(?:persistent|long[\-_]?term)[\-_]?memory"),
            re.compile(r"(?i)(?:memory|memo)[\-_]?(?:store|backend|db|file)"),
            re.compile(r"(?i)(?:VectorStore|FAISS|Chroma|Pinecone|Weaviate).*(?:memory|history)"),
        ]

        has_session_storage = False
        has_persistent_memory = False
        has_context_limit = False
        has_integrity_check = False

        for fpath, content in source_files.items():
            for pattern in session_patterns:
                if pattern.search(content):
                    has_session_storage = True
                    break

            for pattern in memory_patterns:
                if pattern.search(content):
                    has_persistent_memory = True
                    break

            # Check for context window enforcement
            if re.search(r"(?i)(?:max_tokens|max_context|context_window|max_history|truncat)", content):
                has_context_limit = True

            # Check for integrity on conversation data
            if re.search(r"(?i)(?:hmac|digest|hash|signature|checksum|integrity).*(?:message|session|history)", content):
                has_integrity_check = True

        if has_session_storage:
            if not has_integrity_check:
                issues.append((
                    "Session/conversation history stored without integrity checks. "
                    "An attacker with access to storage can inject malicious turns "
                    "into the conversation history to influence future responses.",
                    Severity.HIGH,
                    "Add integrity verification (HMAC or digital signatures) to stored "
                    "conversation data. Validate history integrity before each request.",
                ))
            else:
                issues.append((
                    "Session storage detected with integrity mechanisms present.",
                    Severity.INFO,
                    "Verify integrity checks cover all stored conversation data fields.",
                ))

        if has_persistent_memory:
            issues.append((
                "Persistent memory system detected. User-influenced content stored "
                "in long-term memory can be used for memory injection attacks, where "
                "planted information influences future agent behavior.",
                Severity.HIGH,
                "Sanitize all user content before storing in persistent memory. "
                "Implement access controls and content validation on memory writes. "
                "Separate user-contributed facts from system knowledge.",
            ))

        if has_session_storage and not has_context_limit:
            issues.append((
                "No context window or history size limit detected. An adversary "
                "can overflow the context window with crafted messages to push out "
                "system instructions or safety guidelines.",
                Severity.MEDIUM,
                "Enforce a maximum context window size. Truncate or summarize older "
                "messages. Ensure system instructions are always included regardless "
                "of context length.",
            ))

        # Check for conversation log files in the container
        if cid:
            log_files = await self._exec_in_container(
                "find /app /data /var /tmp -maxdepth 4 -type f "
                "\\( -name '*session*' -o -name '*conversation*' "
                "-o -name '*history*' -o -name '*chat*' \\) "
                "-not -path '*/node_modules/*' -not -path '*/.git/*' "
                "2>/dev/null | head -20"
            )
            if log_files:
                file_count = len(log_files.strip().splitlines())
                # Check file permissions
                perms = await self._exec_in_container(
                    f"ls -la {' '.join(log_files.splitlines()[:10])} 2>/dev/null"
                )
                world_writable = bool(perms and re.search(r"-..-..-rw", perms))

                if world_writable:
                    issues.append((
                        f"Found {file_count} conversation/session file(s) with world-writable "
                        "permissions. Any process can inject content into conversation history.",
                        Severity.HIGH,
                        "Restrict file permissions to the application user only (chmod 600). "
                        "Use a database with authentication for session storage.",
                    ))
                else:
                    issues.append((
                        f"Found {file_count} conversation/session file(s) on disk.",
                        Severity.LOW,
                        "Ensure session files have restrictive permissions and integrity checks.",
                    ))

        if not issues:
            return

        actionable = [i for i in issues if i[1] != Severity.INFO]
        if not actionable:
            worst_severity = Severity.INFO
        else:
            worst_severity = min(
                (s for _, s, _ in actionable),
                key=lambda s: list(Severity).index(s),
            )

        details = "\n".join(
            f"  [{sev.value.upper()}] {desc}" for desc, sev, _ in issues
        )
        remediation_lines = "\n".join(
            f"  - {rem}" for _, _, rem in issues if rem
        )

        self.add_finding(
            title=f"Multi-turn manipulation risks ({len(issues)} issues)",
            description=(
                f"Found {len(issues)} issue(s) related to conversation and session "
                "management that could be exploited for multi-turn manipulation. "
                "Attackers can poison conversation history, inject false memories, "
                "overflow context windows, or tamper with session state to "
                "gradually steer agent behavior toward malicious objectives."
            ),
            severity=worst_severity,
            owasp_llm=["LLM01", "LLM05"],
            owasp_agentic=["ASI01"],
            nist_ai_rmf=["MEASURE", "MANAGE"],
            evidence=[
                Evidence(
                    type="config",
                    summary=f"Multi-turn manipulation risks ({len(issues)} issues)",
                    raw_data=details,
                    location=f"container:{cid}",
                )
            ],
            remediation=remediation_lines,
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
            ],
            cvss_score=7.0 if worst_severity in (Severity.CRITICAL, Severity.HIGH) else 4.5,
            ai_risk_score=8.0,
        )

    # ------------------------------------------------------------------
    # 7. Tool injection
    # ------------------------------------------------------------------

    async def _check_tool_injection(self, source_files: dict[str, str]) -> None:
        """Check for tool/function-calling injection vulnerabilities."""
        tool_definition_patterns = [
            re.compile(r"(?i)tools?\s*[:=]\s*\["),
            re.compile(r"(?i)@tool\b"),
            re.compile(r"(?i)(?:register|add|define)[\-_]?tool\s*\("),
            re.compile(r"(?i)(?:ToolDefinition|BaseTool|FunctionTool|StructuredTool)\b"),
            re.compile(r"(?i)function[\-_]?call(?:ing)?\s*[:=]"),
        ]

        tool_output_patterns = [
            re.compile(r"(?i)tool[\-_]?(?:output|result|response)\s*.*(?:prompt|message|content)"),
            re.compile(r"(?i)(?:append|add|insert)\s*\(.*tool.*(?:output|result)"),
            re.compile(r"(?i)(?:format|f['\"]|template).*tool.*(?:output|result|response)"),
        ]

        param_validation_patterns = [
            re.compile(r"(?i)(?:validate|schema|pydantic|TypedDict|dataclass).*(?:param|arg|input)"),
            re.compile(r"(?i)(?:param|arg).*(?:validate|check|verify|sanitize)"),
        ]

        confirmation_patterns = [
            re.compile(r"(?i)(?:confirm|approve|authorize|human[\-_]?in[\-_]?the[\-_]?loop)"),
            re.compile(r"(?i)(?:require[\-_]?approval|ask[\-_]?user|dangerous[\-_]?action)"),
        ]

        chain_restriction_patterns = [
            re.compile(r"(?i)(?:max[\-_]?(?:steps|iterations|tools|calls|chain))"),
            re.compile(r"(?i)(?:tool[\-_]?(?:limit|budget|quota|cap))"),
        ]

        issues: list[tuple[str, Severity, str]] = []
        has_tool_definitions = False
        tool_def_files: list[str] = []

        for fpath, content in source_files.items():
            for pattern in tool_definition_patterns:
                if pattern.search(content):
                    has_tool_definitions = True
                    tool_def_files.append(fpath)
                    break

        if not has_tool_definitions:
            return

        # Check for tool definitions accessible to user input
        has_dynamic_tools = False
        for fpath, content in source_files.items():
            if re.search(r"(?i)(?:user|input|request).*tool.*(?:name|def|spec)", content):
                has_dynamic_tools = True
                issues.append((
                    f"Tool definitions may be influenced by user input in {fpath}. "
                    "An attacker could inject custom tool definitions or modify "
                    "existing ones to execute arbitrary operations.",
                    Severity.CRITICAL,
                    "Never allow user input to define or modify tool specifications. "
                    "Use a static, pre-defined tool registry.",
                ))
                break

        # Check for missing parameter validation
        has_param_validation = False
        for fpath, content in source_files.items():
            for pattern in param_validation_patterns:
                if pattern.search(content):
                    has_param_validation = True
                    break
            if has_param_validation:
                break

        if not has_param_validation:
            issues.append((
                "No tool parameter validation detected. Tool inputs from the LLM "
                "are passed without schema validation, allowing the model to supply "
                "unexpected or malicious parameter values.",
                Severity.HIGH,
                "Add Pydantic models or JSON Schema validation for all tool parameters. "
                "Enforce type checking and value constraints.",
            ))

        # Check for unsanitized tool output injection
        has_output_injection = False
        for fpath, content in source_files.items():
            for pattern in tool_output_patterns:
                if pattern.search(content):
                    has_output_injection = True
                    issues.append((
                        f"Tool output injected back into prompts without sanitization "
                        f"in {fpath}. Malicious tool output could contain prompt "
                        "injection payloads that hijack the agent.",
                        Severity.HIGH,
                        "Sanitize and escape tool output before including it in prompts. "
                        "Use structured output formats and validate against expected schemas.",
                    ))
                    break
            if has_output_injection:
                break

        # Check for unrestricted tool chaining
        has_chain_limits = False
        for fpath, content in source_files.items():
            for pattern in chain_restriction_patterns:
                if pattern.search(content):
                    has_chain_limits = True
                    break
            if has_chain_limits:
                break

        if not has_chain_limits:
            issues.append((
                "No tool chaining limits detected. The agent may call tools in an "
                "unbounded loop, enabling resource exhaustion or progressive "
                "exploitation through chained tool calls.",
                Severity.MEDIUM,
                "Set a maximum number of tool calls per request. Implement a tool "
                "call budget and abort execution when exceeded.",
            ))

        # Check for confirmation on dangerous operations
        has_confirmation = False
        for fpath, content in source_files.items():
            for pattern in confirmation_patterns:
                if pattern.search(content):
                    has_confirmation = True
                    break
            if has_confirmation:
                break

        if not has_confirmation:
            issues.append((
                "No confirmation mechanism for dangerous tool operations. "
                "High-risk tools (file write, shell exec, API calls) can be "
                "invoked without human approval.",
                Severity.HIGH,
                "Require explicit user confirmation for destructive or high-risk "
                "tool operations. Classify tools by risk level and apply "
                "appropriate approval workflows.",
            ))

        if not issues:
            return

        worst_severity = min(
            (s for _, s, _ in issues),
            key=lambda s: list(Severity).index(s),
        )

        details = "\n".join(
            f"  [{sev.value.upper()}] {desc}" for desc, sev, _ in issues
        )
        remediation_lines = "\n".join(
            f"  - {rem}" for _, _, rem in issues
        )

        self.add_finding(
            title=f"Tool injection vulnerabilities ({len(issues)} issues)",
            description=(
                f"Found {len(issues)} tool/function-calling security issue(s) in "
                f"{len(tool_def_files)} file(s) with tool definitions. These "
                "vulnerabilities allow adversaries to manipulate tool execution "
                "through injection attacks, parameter tampering, output poisoning, "
                "or unrestricted chaining."
            ),
            severity=worst_severity,
            owasp_llm=["LLM01", "LLM06"],
            owasp_agentic=["ASI02", "ASI05"],
            nist_ai_rmf=["GOVERN", "MANAGE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary=f"Tool injection issues ({len(issues)} findings)",
                    raw_data=details,
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=remediation_lines,
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
            ],
            cvss_score=9.0 if worst_severity == Severity.CRITICAL else 7.0,
            ai_risk_score=8.5,
        )
