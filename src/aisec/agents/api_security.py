"""API security agent for endpoint scanning and auth/rate-limit checks."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Common AI API endpoint paths to probe
AI_API_PATHS = [
    # OpenAI-compatible
    "/v1/models", "/v1/completions", "/v1/chat/completions",
    "/v1/embeddings", "/v1/images/generations", "/v1/audio/transcriptions",
    # Ollama
    "/api/generate", "/api/chat", "/api/tags", "/api/show",
    # General API discovery
    "/health", "/healthz", "/ready", "/readyz",
    "/metrics", "/prometheus/metrics",
    "/docs", "/redoc", "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
    # Admin/debug
    "/admin", "/debug", "/_debug", "/internal",
    "/api/v1/status", "/api/v1/config",
]

# Nuclei templates directory
_RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "nuclei"


class APISecurityAgent(BaseAgent):
    """Scan exposed API endpoints for security misconfigurations."""

    name: ClassVar[str] = "api_security"
    description: ClassVar[str] = (
        "Probes AI API endpoints for authentication bypass, rate limiting "
        "gaps, CORS misconfigurations, information disclosure, and GraphQL "
        "introspection. Uses Nuclei templates when available."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM06", "LLM10", "ASI02", "ASI03"]
    depends_on: ClassVar[list[str]] = ["network"]

    async def analyze(self) -> None:
        """Run API security checks."""
        endpoints = await self._discover_endpoints()
        if not endpoints:
            self.add_finding(
                title="No API endpoints discovered for testing",
                description=(
                    "No network endpoints were discovered from the NetworkAgent "
                    "results. API security testing could not be performed."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM10"],
            )
            return

        await self._run_nuclei(endpoints)
        await self._check_auth_bypass(endpoints)
        await self._check_rate_limiting(endpoints)
        await self._check_cors(endpoints)
        await self._check_info_disclosure(endpoints)
        await self._check_graphql_introspection(endpoints)
        await self._check_verbose_errors(endpoints)

    async def _discover_endpoints(self) -> list[str]:
        """Discover API endpoints from NetworkAgent results and container inspection."""
        endpoints: list[str] = []

        # Get exposed ports from network agent results
        network_result = self.context.agent_results.get("network")
        if network_result:
            for finding in network_result.findings:
                for evidence in finding.evidence:
                    # Try to extract port information
                    if "port" in evidence.summary.lower():
                        # Extract port numbers from evidence
                        import re
                        ports = re.findall(r"(\d{2,5})", evidence.raw_data)
                        for port in ports:
                            port_int = int(port)
                            if 80 <= port_int <= 65535:
                                endpoints.append(f"http://localhost:{port}")

        # Fallback: inspect container for exposed ports
        cid = self.context.container_id
        if cid and not endpoints:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "inspect",
                    "--format", "{{json .Config.ExposedPorts}}", cid,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    ports_data = stdout.decode(errors="replace").strip()
                    if ports_data and ports_data != "null":
                        ports_dict = json.loads(ports_data)
                        for port_spec in ports_dict:
                            port = port_spec.split("/")[0]
                            endpoints.append(f"http://localhost:{port}")
            except Exception:
                pass

        # Deduplicate
        return list(dict.fromkeys(endpoints))

    async def _run_nuclei(self, endpoints: list[str]) -> bool:
        """Run Nuclei with AI-specific templates."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                return False
        except (FileNotFoundError, OSError):
            return False

        templates_dir = _RULES_DIR
        if not templates_dir.exists():
            return False

        for endpoint in endpoints[:5]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nuclei", "-u", endpoint,
                    "-t", str(templates_dir),
                    "-jsonl", "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode(errors="replace")

                for line in output.strip().splitlines():
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                        severity_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                            "info": Severity.INFO,
                        }
                        sev = severity_map.get(
                            result.get("info", {}).get("severity", "medium"),
                            Severity.MEDIUM,
                        )
                        self.add_finding(
                            title=f"Nuclei: {result.get('info', {}).get('name', 'Unknown')}",
                            description=result.get("info", {}).get("description", ""),
                            severity=sev,
                            owasp_llm=["LLM10"],
                            owasp_agentic=["ASI03"],
                            evidence=[
                                Evidence(
                                    type="api_response",
                                    summary=f"Nuclei finding at {endpoint}",
                                    raw_data=json.dumps(result)[:500],
                                    location=result.get("matched-at", endpoint),
                                )
                            ],
                            remediation=result.get("info", {}).get("remediation", ""),
                        )
                    except json.JSONDecodeError:
                        continue
            except Exception as exc:
                logger.warning("Nuclei scan failed for %s: %s", endpoint, exc)

        return True

    async def _http_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 5,
    ) -> tuple[int, dict[str, str], str]:
        """Make an HTTP request using httpx from within the container or host."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.request(
                    method, url,
                    headers=headers or {},
                    content=body,
                )
                return (
                    response.status_code,
                    dict(response.headers),
                    response.text[:4096],
                )
        except Exception:
            return (0, {}, "")

    async def _check_auth_bypass(self, endpoints: list[str]) -> None:
        """Check for unauthenticated access to API endpoints."""
        unauth_endpoints: list[tuple[str, str, int]] = []

        for base in endpoints[:5]:
            for path in AI_API_PATHS[:15]:
                url = f"{base}{path}"
                status, headers, body = await self._http_request(url)
                if status in (200, 201) and body:
                    # Check if response contains actual data (not just "unauthorized")
                    body_lower = body.lower()
                    if not any(w in body_lower for w in ["unauthorized", "forbidden", "login", "authenticate"]):
                        unauth_endpoints.append((path, body[:200], status))

        if unauth_endpoints:
            details = "\n".join(
                f"  {path} (HTTP {status}): {body[:100]}"
                for path, body, status in unauth_endpoints[:10]
            )
            self.add_finding(
                title=f"Unauthenticated API endpoints accessible ({len(unauth_endpoints)})",
                description=(
                    f"Found {len(unauth_endpoints)} API endpoint(s) accessible "
                    "without authentication. This includes AI inference endpoints "
                    "that could be abused for unauthorized model access or "
                    "resource consumption."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06", "LLM10"],
                owasp_agentic=["ASI03"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    Evidence(
                        type="api_response",
                        summary=f"{len(unauth_endpoints)} unauth endpoints",
                        raw_data=details,
                        location=endpoints[0] if endpoints else "",
                    )
                ],
                remediation=(
                    "Implement authentication (API keys, OAuth2, JWT) on all "
                    "API endpoints. Ensure inference endpoints require valid "
                    "credentials before processing requests."
                ),
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    async def _check_rate_limiting(self, endpoints: list[str]) -> None:
        """Check for rate limiting on API endpoints."""
        for base in endpoints[:3]:
            # Try a known AI endpoint path or the root
            test_paths = ["/v1/models", "/api/tags", "/health", "/"]
            target_url = None
            for path in test_paths:
                url = f"{base}{path}"
                status, _, _ = await self._http_request(url)
                if status in (200, 201):
                    target_url = url
                    break

            if not target_url:
                continue

            # Send rapid requests to check for rate limiting
            got_rate_limited = False
            responses: list[int] = []
            for _ in range(20):
                status, headers, _ = await self._http_request(target_url)
                responses.append(status)
                if status == 429 or "retry-after" in {k.lower() for k in headers}:
                    got_rate_limited = True
                    break

            # Check for rate limit headers
            _, last_headers, _ = await self._http_request(target_url)
            has_rate_headers = any(
                h.lower().startswith(("x-ratelimit", "ratelimit", "x-rate-limit"))
                for h in last_headers
            )

            if not got_rate_limited and not has_rate_headers:
                self.add_finding(
                    title=f"No rate limiting detected on {base}",
                    description=(
                        "Sent 20 rapid requests without receiving a 429 response "
                        "or rate limit headers. Without rate limiting, the API is "
                        "vulnerable to resource exhaustion, cost attacks, and "
                        "denial of service."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM10"],
                    owasp_agentic=["ASI02"],
                    nist_ai_rmf=["MANAGE"],
                    evidence=[
                        Evidence(
                            type="api_response",
                            summary="No rate limiting",
                            raw_data=f"Responses: {responses[:20]}",
                            location=target_url,
                        )
                    ],
                    remediation=(
                        "Implement rate limiting on all API endpoints. Use "
                        "token bucket or sliding window algorithms. Return "
                        "429 status with Retry-After header when limits are exceeded."
                    ),
                    cvss_score=5.0,
                )

    async def _check_cors(self, endpoints: list[str]) -> None:
        """Check for overly permissive CORS configuration."""
        for base in endpoints[:3]:
            status, headers, _ = await self._http_request(
                base,
                headers={"Origin": "https://evil.example.com"},
            )
            if status == 0:
                continue

            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                self.add_finding(
                    title=f"Wildcard CORS policy on {base}",
                    description=(
                        "The API returns Access-Control-Allow-Origin: * which "
                        "allows any website to make cross-origin requests. This "
                        "could enable browser-based attacks against the AI API."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM06"],
                    owasp_agentic=["ASI03"],
                    evidence=[
                        Evidence(
                            type="api_response",
                            summary="Wildcard CORS",
                            raw_data=f"Access-Control-Allow-Origin: {acao}",
                            location=base,
                        )
                    ],
                    remediation=(
                        "Restrict CORS to specific trusted origins. Never use "
                        "wildcard (*) in production."
                    ),
                    cvss_score=5.0,
                )
            elif "evil.example.com" in acao:
                self.add_finding(
                    title=f"CORS reflects arbitrary origin on {base}",
                    description=(
                        "The API reflects the Origin header value in "
                        "Access-Control-Allow-Origin, allowing any origin "
                        "to make authenticated cross-origin requests."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM06"],
                    owasp_agentic=["ASI03"],
                    evidence=[
                        Evidence(
                            type="api_response",
                            summary="CORS origin reflection",
                            raw_data=f"Origin: evil.example.com -> ACAO: {acao}",
                            location=base,
                        )
                    ],
                    remediation="Validate the Origin header against a whitelist of trusted domains.",
                    cvss_score=7.0,
                )

    async def _check_info_disclosure(self, endpoints: list[str]) -> None:
        """Check for information disclosure through debug/docs endpoints."""
        disclosure_hits: list[tuple[str, str, str]] = []

        info_paths = [
            ("/docs", "API documentation"),
            ("/swagger.json", "Swagger/OpenAPI specification"),
            ("/openapi.json", "OpenAPI specification"),
            ("/redoc", "ReDoc API documentation"),
            ("/metrics", "Prometheus metrics"),
            ("/debug", "Debug interface"),
            ("/admin", "Admin panel"),
            ("/internal", "Internal endpoints"),
            ("/api-docs", "API documentation"),
        ]

        for base in endpoints[:3]:
            for path, label in info_paths:
                url = f"{base}{path}"
                status, _, body = await self._http_request(url)
                if status == 200 and len(body) > 50:
                    disclosure_hits.append((url, label, body[:150]))

        if disclosure_hits:
            details = "\n".join(
                f"  {url} ({label}): {body[:80]}"
                for url, label, body in disclosure_hits[:10]
            )
            self.add_finding(
                title=f"Information disclosure via debug/docs endpoints ({len(disclosure_hits)})",
                description=(
                    f"Found {len(disclosure_hits)} endpoint(s) exposing internal "
                    "information such as API documentation, metrics, or debug "
                    "interfaces. This information can help attackers understand "
                    "the API structure and craft targeted attacks."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI03"],
                evidence=[
                    Evidence(
                        type="api_response",
                        summary="Information disclosure",
                        raw_data=details,
                        location=endpoints[0] if endpoints else "",
                    )
                ],
                remediation=(
                    "Disable documentation endpoints (/docs, /swagger, /redoc) "
                    "in production. Restrict /metrics and /debug to internal "
                    "networks only. Use authentication for admin endpoints."
                ),
                cvss_score=4.0,
            )

    async def _check_graphql_introspection(self, endpoints: list[str]) -> None:
        """Check for enabled GraphQL introspection."""
        for base in endpoints[:3]:
            url = f"{base}/graphql"
            status, _, body = await self._http_request(
                url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"query": "{__schema{types{name}}}"}',
            )
            if status == 200 and "__schema" in body:
                self.add_finding(
                    title=f"GraphQL introspection enabled on {base}",
                    description=(
                        "GraphQL introspection is enabled, allowing attackers to "
                        "enumerate the entire API schema including types, queries, "
                        "mutations, and subscriptions."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM06"],
                    owasp_agentic=["ASI03"],
                    evidence=[
                        Evidence(
                            type="api_response",
                            summary="GraphQL introspection",
                            raw_data=body[:300],
                            location=url,
                        )
                    ],
                    remediation=(
                        "Disable GraphQL introspection in production environments."
                    ),
                    cvss_score=4.0,
                )

    async def _check_verbose_errors(self, endpoints: list[str]) -> None:
        """Check for verbose error messages that leak information."""
        for base in endpoints[:3]:
            # Send malformed request to trigger errors
            for path in ["/v1/completions", "/api/generate", "/"]:
                url = f"{base}{path}"
                status, _, body = await self._http_request(
                    url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body='{"invalid": "malformed',
                )
                if status >= 400 and body:
                    body_lower = body.lower()
                    stack_trace_indicators = [
                        "traceback", "at line", "stack trace",
                        "file \"", "exception in", "error at",
                        "debug", "internal server error",
                    ]
                    if any(ind in body_lower for ind in stack_trace_indicators):
                        self.add_finding(
                            title=f"Verbose error messages on {base}",
                            description=(
                                "The API returns detailed error messages including "
                                "stack traces or internal paths. This information "
                                "helps attackers understand the application structure."
                            ),
                            severity=Severity.LOW,
                            owasp_llm=["LLM06"],
                            evidence=[
                                Evidence(
                                    type="api_response",
                                    summary="Verbose error",
                                    raw_data=body[:400],
                                    location=url,
                                )
                            ],
                            remediation=(
                                "Return generic error messages in production. "
                                "Log detailed errors server-side only."
                            ),
                            cvss_score=3.0,
                        )
                        break  # One finding per endpoint is enough
