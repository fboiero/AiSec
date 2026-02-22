"""Inter-service communication security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Webhook handler patterns (should have HMAC/signature verification)
WEBHOOK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Flask webhook", re.compile(r'@app\.(?:route|post)\s*\([^)]*(?:webhook|hook|callback)[^)]*\)', re.IGNORECASE)),
    ("FastAPI webhook", re.compile(r'@(?:app|router)\.post\s*\([^)]*(?:webhook|hook|callback)[^)]*\)', re.IGNORECASE)),
    ("Django webhook", re.compile(r'(?:path|url)\s*\([^)]*(?:webhook|hook|callback)[^)]*\)', re.IGNORECASE)),
    ("Generic webhook handler", re.compile(r'def\s+\w*(?:webhook|hook|callback)\w*\s*\(', re.IGNORECASE)),
]

HMAC_PATTERNS = re.compile(
    r'hmac\.(?:new|compare_digest)|verify_signature|validate_signature|'
    r'X-Hub-Signature|X-Signature|X-Webhook-Signature|webhook_secret',
    re.IGNORECASE,
)

# Message queue connection patterns
MQ_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "RabbitMQ without credentials",
        re.compile(r'(?:pika\.ConnectionParameters|pika\.URLParameters)\s*\([^)]*\)(?!.*(?:credentials|password))'),
        "Always use authenticated connections: pika.PlainCredentials(user, password).",
    ),
    (
        "Kafka without SASL",
        re.compile(r'KafkaProducer|KafkaConsumer\s*\([^)]*\)(?!.*(?:sasl|security_protocol))'),
        "Enable SASL authentication: security_protocol='SASL_SSL', sasl_mechanism='SCRAM-SHA-256'.",
    ),
    (
        "Redis without password",
        re.compile(r'(?:Redis|StrictRedis)\s*\([^)]*\)(?!.*password)'),
        "Use password authentication: Redis(host, password=secret).",
    ),
]

# gRPC patterns
GRPC_REFLECTION_PATTERN = re.compile(
    r'(?:grpc_reflection|enable_server_reflection|reflection\.enable)',
    re.IGNORECASE,
)

# Internal HTTP patterns (non-TLS)
HTTP_INTERNAL_PATTERNS = re.compile(
    r'(?:http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168))',
)

# Callback URL patterns (SSRF risk)
CALLBACK_URL_PATTERNS = re.compile(
    r'callback_url|redirect_uri|return_url|webhook_url|notify_url',
    re.IGNORECASE,
)

CALLBACK_VALIDATION_PATTERNS = re.compile(
    r'(?:validate_url|url_validator|allowed_hosts|ALLOWED_HOSTS|urlparse.*scheme)',
    re.IGNORECASE,
)


class InterServiceSecurityAgent(BaseAgent):
    """Checks inter-service communication security."""

    name: ClassVar[str] = "inter_service"
    description: ClassVar[str] = (
        "Analyzes inter-service communication security: webhook HMAC verification, "
        "mTLS usage, message queue authentication, gRPC reflection, and callback "
        "URL validation."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM07", "LLM10", "ASI03", "ASI08"]
    depends_on: ClassVar[list[str]] = ["network", "api_security"]

    async def analyze(self) -> None:
        """Analyze inter-service communication security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for inter-service analysis",
                description="No source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM07"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        self._check_webhook_security(all_content, combined)
        self._check_mtls_absence(all_content)
        self._check_message_queue_auth(all_content)
        self._check_grpc_reflection(all_content)
        self._check_callback_validation(all_content, combined)
        await self._check_network_policies()

    def _check_webhook_security(self, files: dict[str, str], combined: str) -> None:
        """Check webhook handlers for HMAC/signature verification."""
        webhook_found = False
        webhook_files: list[tuple[str, str]] = []

        for fpath, content in files.items():
            for name, pattern in WEBHOOK_PATTERNS:
                matches = list(pattern.finditer(content))
                if matches:
                    webhook_found = True
                    for m in matches:
                        line = content[:m.start()].count("\n") + 1
                        webhook_files.append((fpath, f"line {line}: {name}"))

        if not webhook_found:
            return

        has_hmac = bool(HMAC_PATTERNS.search(combined))

        if not has_hmac:
            details = "\n".join(f"  {f}: {loc}" for f, loc in webhook_files[:10])
            self.add_finding(
                title=f"Webhook handlers without HMAC verification ({len(webhook_files)})",
                description=(
                    f"Found {len(webhook_files)} webhook handler(s) without HMAC or "
                    "signature verification. Unverified webhooks can be forged by "
                    "attackers to trigger unauthorized actions."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM07"],
                owasp_agentic=["ASI03", "ASI08"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Webhook handlers without HMAC",
                        raw_data=details,
                        location=webhook_files[0][0] if webhook_files else "",
                    )
                ],
                remediation=(
                    "Implement HMAC signature verification for all webhook endpoints. "
                    "Use hmac.compare_digest() for timing-safe comparison."
                ),
                cvss_score=7.5,
            )

    def _check_mtls_absence(self, files: dict[str, str]) -> None:
        """Check for internal HTTP connections without TLS."""
        insecure_connections: list[tuple[str, int]] = []

        for fpath, content in files.items():
            matches = list(HTTP_INTERNAL_PATTERNS.finditer(content))
            for m in matches:
                line = content[:m.start()].count("\n") + 1
                insecure_connections.append((fpath, line))

        if insecure_connections:
            details = "\n".join(
                f"  {f}:{line}" for f, line in insecure_connections[:15]
            )
            self.add_finding(
                title=f"Internal HTTP without TLS ({len(insecure_connections)} connections)",
                description=(
                    f"Found {len(insecure_connections)} internal HTTP (non-TLS) "
                    "connections. Internal service-to-service communication should "
                    "use TLS/mTLS to prevent data interception."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM07"],
                owasp_agentic=["ASI08"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Internal HTTP connections",
                        raw_data=details,
                        location=insecure_connections[0][0] if insecure_connections else "",
                    )
                ],
                remediation=(
                    "Use HTTPS for all service-to-service communication. Implement "
                    "mTLS for mutual authentication between services."
                ),
                cvss_score=5.0,
            )

    def _check_message_queue_auth(self, files: dict[str, str]) -> None:
        """Check message queue connections for authentication."""
        for fpath, content in files.items():
            for name, pattern, remediation in MQ_PATTERNS:
                matches = list(pattern.finditer(content))
                for m in matches[:2]:
                    line = content[:m.start()].count("\n") + 1
                    self.add_finding(
                        title=f"Message queue without auth: {name}",
                        description=(
                            f"Message queue connection at {fpath}:{line} appears to "
                            "lack authentication. Unauthenticated message queues "
                            "allow unauthorized message injection."
                        ),
                        severity=Severity.HIGH,
                        owasp_llm=["LLM07"],
                        owasp_agentic=["ASI03"],
                        evidence=[
                            Evidence(
                                type="file_content",
                                summary=f"{name} at {fpath}:{line}",
                                raw_data=content[max(0, m.start() - 20):m.end() + 40][:200],
                                location=f"{fpath}:{line}",
                            )
                        ],
                        remediation=remediation,
                        cvss_score=7.0,
                    )

    def _check_grpc_reflection(self, files: dict[str, str]) -> None:
        """Check for gRPC reflection enabled (should be disabled in production)."""
        for fpath, content in files.items():
            matches = list(GRPC_REFLECTION_PATTERN.finditer(content))
            for m in matches:
                line = content[:m.start()].count("\n") + 1
                self.add_finding(
                    title="gRPC reflection enabled",
                    description=(
                        f"gRPC reflection is enabled at {fpath}:{line}. "
                        "This exposes the full service API schema and should be "
                        "disabled in production."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM07"],
                    owasp_agentic=["ASI03"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"gRPC reflection at {fpath}:{line}",
                            raw_data=content[max(0, m.start() - 20):m.end() + 40][:200],
                            location=f"{fpath}:{line}",
                        )
                    ],
                    remediation=(
                        "Disable gRPC reflection in production. Use environment-based "
                        "configuration to enable it only in development."
                    ),
                    cvss_score=4.0,
                )

    def _check_callback_validation(self, files: dict[str, str], combined: str) -> None:
        """Check for unvalidated callback/redirect URLs (SSRF risk)."""
        callback_refs: list[tuple[str, int]] = []

        for fpath, content in files.items():
            matches = list(CALLBACK_URL_PATTERNS.finditer(content))
            for m in matches:
                line = content[:m.start()].count("\n") + 1
                callback_refs.append((fpath, line))

        if not callback_refs:
            return

        has_validation = bool(CALLBACK_VALIDATION_PATTERNS.search(combined))

        if not has_validation:
            details = "\n".join(f"  {f}:{line}" for f, line in callback_refs[:10])
            self.add_finding(
                title=f"Unvalidated callback URLs ({len(callback_refs)} references)",
                description=(
                    f"Found {len(callback_refs)} callback/redirect URL reference(s) "
                    "without URL validation. Unvalidated callback URLs can be "
                    "exploited for SSRF (Server-Side Request Forgery) attacks."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM10"],
                owasp_agentic=["ASI08"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Unvalidated callback URLs",
                        raw_data=details,
                        location=callback_refs[0][0] if callback_refs else "",
                    )
                ],
                remediation=(
                    "Validate all callback URLs against an allowlist of permitted "
                    "hosts and schemes. Never allow callbacks to internal IPs."
                ),
                cvss_score=7.0,
            )

    async def _check_network_policies(self) -> None:
        """Check for network policy presence in K8s/Docker configs."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c",
                "find / -maxdepth 5 -type f \\( -name '*.yaml' -o -name '*.yml' \\) "
                "2>/dev/null | head -50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return

            yaml_files = stdout.decode(errors="replace").splitlines()
        except Exception:
            return

        has_network_policy = False
        for fpath in yaml_files:
            content = await self._read_file(fpath.strip())
            if content and "NetworkPolicy" in content:
                has_network_policy = True
                break

        if yaml_files and not has_network_policy:
            # Only flag if there are K8s manifests but no network policies
            has_k8s = any(
                await self._read_file(f.strip()) and "apiVersion" in (await self._read_file_cached(f.strip(), {}))
                for f in yaml_files[:10]
            )
            if has_k8s:
                self.add_finding(
                    title="No Kubernetes NetworkPolicy found",
                    description=(
                        "Kubernetes manifests found but no NetworkPolicy resources. "
                        "Without network policies, all pods can communicate freely."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM07"],
                    owasp_agentic=["ASI08"],
                    remediation=(
                        "Add NetworkPolicy resources to restrict pod-to-pod communication "
                        "to only necessary connections."
                    ),
                    cvss_score=5.0,
                )

    async def _read_file_cached(self, fpath: str, cache: dict[str, str]) -> str:
        """Read file with simple cache."""
        if fpath not in cache:
            cache[fpath] = await self._read_file(fpath)
        return cache[fpath]

    async def _collect_source_files(self) -> list[str]:
        """Collect source file paths from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f "
            "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.go' \\) "
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
