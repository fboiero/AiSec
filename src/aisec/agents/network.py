"""Network security analysis agent."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Ports commonly associated with sensitive or management services.
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    2375: "Docker daemon (unencrypted)",
    2376: "Docker daemon (TLS)",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    8500: "Consul",
    2181: "ZooKeeper",
    4040: "Spark UI",
}


class NetworkAgent(BaseAgent):
    """Inspect container network configuration and exposed services."""

    name: ClassVar[str] = "network"
    description: ClassVar[str] = (
        "Analyses exposed ports, WebSocket endpoints, TLS configuration, "
        "outbound network connections, model extraction defenses, "
        "and model API security on the target container."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM09", "ASI07", "ASI08"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Run all network security checks."""
        container_info = await self._get_container_info()
        if container_info is None:
            logger.warning("No container info available; skipping network analysis")
            return

        await self._check_exposed_ports(container_info)
        await self._check_websocket_endpoints(container_info)
        await self._check_tls_configuration(container_info)
        await self._check_outbound_connections()
        await self._check_model_extraction_defenses(container_info)
        await self._check_model_api_security(container_info)

    # ------------------------------------------------------------------
    # Container introspection helpers
    # ------------------------------------------------------------------

    async def _get_container_info(self) -> dict[str, Any] | None:
        """Return docker inspect output for the target container."""
        dm = self.context.docker_manager
        if dm is None:
            logger.debug("docker_manager not set; attempting CLI fallback")
            return await self._inspect_via_cli()
        try:
            info = await asyncio.to_thread(dm.inspect_target)
            return info if info else await self._inspect_via_cli()
        except Exception:
            logger.debug("docker_manager.inspect_target failed; trying CLI")
            return await self._inspect_via_cli()

    async def _inspect_via_cli(self) -> dict[str, Any] | None:
        cid = self.context.container_id
        if not cid:
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return None
            data = json.loads(stdout)
            return data[0] if isinstance(data, list) else data
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    async def _check_exposed_ports(self, info: dict[str, Any]) -> None:
        """Identify exposed ports and flag sensitive services."""
        # Gather ports from NetworkSettings -> Ports and Config -> ExposedPorts
        ports_map: dict[str, Any] = (
            info.get("NetworkSettings", {}).get("Ports") or {}
        )
        exposed_cfg: dict[str, Any] = (
            info.get("Config", {}).get("ExposedPorts") or {}
        )

        # Merge keys  --  port strings look like "8080/tcp"
        all_port_keys = set(ports_map.keys()) | set(exposed_cfg.keys())

        if not all_port_keys:
            return

        for port_str in sorted(all_port_keys):
            port_num = int(port_str.split("/")[0])
            proto = port_str.split("/")[1] if "/" in port_str else "tcp"

            # Check if the port is bound to the host
            bindings = ports_map.get(port_str) or []
            host_bound = any(
                b.get("HostIp", "0.0.0.0") in ("0.0.0.0", "", "::")
                for b in bindings
                if isinstance(b, dict)
            )

            if port_num in SENSITIVE_PORTS:
                svc = SENSITIVE_PORTS[port_num]
                severity = Severity.HIGH if host_bound else Severity.MEDIUM
                self.add_finding(
                    title=f"Sensitive service exposed: {svc} (port {port_num}/{proto})",
                    description=(
                        f"The container exposes port {port_num}/{proto} ({svc}). "
                        f"{'This port is bound to the host on all interfaces.' if host_bound else 'The port is exposed only within the Docker network.'} "
                        "Exposing management or database services increases the attack surface."
                    ),
                    severity=severity,
                    owasp_llm=["LLM09"],
                    owasp_agentic=["ASI07", "ASI08"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary=f"Port {port_num}/{proto} ({svc}) exposed",
                            raw_data=json.dumps({"port": port_str, "bindings": bindings}),
                            location=f"container:{self.context.container_id}",
                        )
                    ],
                    remediation=(
                        f"Remove or restrict access to port {port_num}. "
                        "Use Docker network isolation and only expose ports that are "
                        "strictly necessary for the agent's operation."
                    ),
                    cvss_score=7.5 if host_bound else 5.0,
                )
            elif host_bound:
                self.add_finding(
                    title=f"Port {port_num}/{proto} bound to all host interfaces",
                    description=(
                        f"Port {port_num}/{proto} is bound to 0.0.0.0 on the host, "
                        "making it reachable from any network interface."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM09"],
                    owasp_agentic=["ASI07"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary=f"Host-bound port {port_num}/{proto}",
                            raw_data=json.dumps({"port": port_str, "bindings": bindings}),
                            location=f"container:{self.context.container_id}",
                        )
                    ],
                    remediation=(
                        "Bind the port to 127.0.0.1 or a specific interface instead "
                        "of 0.0.0.0. Consider using Docker network policies."
                    ),
                    cvss_score=4.3,
                )

    async def _check_websocket_endpoints(self, info: dict[str, Any]) -> None:
        """Look for WebSocket endpoints and check Origin validation."""
        cid = self.context.container_id
        if not cid:
            return

        # Attempt to list listening sockets inside the container
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            listeners = stdout.decode(errors="replace") if proc.returncode == 0 else ""
        except Exception:
            listeners = ""

        # Heuristic: search for common WebSocket frameworks in the process
        # environment or configuration files.
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "grep -r -l 'websocket\\|ws://' /app /src /opt 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            ws_files = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            ws_files = ""

        if not ws_files:
            return

        # Check for Origin header validation
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "grep -r -i 'origin\\|check_origin\\|allowed_origins\\|cors' /app /src /opt 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            origin_checks = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            origin_checks = ""

        if ws_files and not origin_checks:
            self.add_finding(
                title="WebSocket endpoint lacks Origin validation",
                description=(
                    "WebSocket endpoints were detected but no Origin header "
                    "validation was found. This may allow cross-site WebSocket "
                    "hijacking (CSWSH) attacks, enabling an attacker to interact "
                    "with the AI agent from a malicious web page."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="Files referencing WebSocket",
                        raw_data=ws_files[:2000],
                        location=f"container:{cid}",
                    ),
                ],
                remediation=(
                    "Implement Origin header validation on all WebSocket endpoints. "
                    "Use an allow-list of trusted origins and reject connections from "
                    "unknown origins. Consider adding authentication tokens to the "
                    "WebSocket handshake."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets",
                ],
                cvss_score=7.1,
            )

    async def _check_tls_configuration(self, info: dict[str, Any]) -> None:
        """Check whether TLS is configured for exposed HTTP services."""
        cid = self.context.container_id
        if not cid:
            return

        # Search for TLS certificate and key files
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find / -maxdepth 5 \\( -name '*.pem' -o -name '*.crt' -o -name '*.key' \\) 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            tls_files = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            tls_files = ""

        # Check environment for TLS-related configuration
        env_vars = info.get("Config", {}).get("Env") or []
        tls_env = [e for e in env_vars if any(k in e.upper() for k in ("TLS", "SSL", "HTTPS", "CERT"))]

        if not tls_files and not tls_env:
            # Only flag if there are exposed HTTP-ish ports
            ports_map = info.get("NetworkSettings", {}).get("Ports") or {}
            http_ports = [
                p for p in ports_map
                if int(p.split("/")[0]) in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000)
            ]
            if http_ports:
                self.add_finding(
                    title="No TLS configuration detected for HTTP services",
                    description=(
                        "The container exposes HTTP service ports but no TLS "
                        "certificates, key files, or TLS-related environment "
                        "variables were found. Communication with the AI agent "
                        "may be unencrypted, exposing prompts, responses, and "
                        "credentials to network interception."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM09"],
                    owasp_agentic=["ASI07", "ASI08"],
                    evidence=[
                        Evidence(
                            type="config",
                            summary="HTTP ports without TLS",
                            raw_data=json.dumps({"http_ports": http_ports}),
                            location=f"container:{cid}",
                        )
                    ],
                    remediation=(
                        "Configure TLS for all HTTP services. Use a reverse proxy "
                        "(e.g., nginx, Caddy) with a valid TLS certificate, or "
                        "configure TLS directly in the application. At minimum, "
                        "use a self-signed certificate for development environments."
                    ),
                    cvss_score=6.5,
                )

    async def _check_outbound_connections(self) -> None:
        """Identify active outbound network connections from the container."""
        cid = self.context.container_id
        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null || true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            connections = stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            connections = ""

        if not connections:
            return

        # Parse for ESTABLISHED outbound connections
        outbound_lines = []
        for line in connections.splitlines():
            if "ESTAB" in line or "ESTABLISHED" in line:
                outbound_lines.append(line.strip())

        if not outbound_lines:
            return

        # Check for network restriction policy (--network=none or custom network)
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect",
                "--format", "{{json .NetworkSettings.Networks}}",
                cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            net_info = stdout.decode(errors="replace").strip() if proc.returncode == 0 else "{}"
        except Exception:
            net_info = "{}"

        is_bridge = "bridge" in net_info.lower()

        self.add_finding(
            title="Active outbound network connections detected",
            description=(
                f"The container has {len(outbound_lines)} active outbound "
                "connection(s). AI agents with unrestricted outbound access "
                "may exfiltrate data, contact command-and-control servers, "
                "or be exploited for server-side request forgery (SSRF)."
                + (" The container is on the default bridge network, which "
                   "provides unrestricted outbound access." if is_bridge else "")
            ),
            severity=Severity.MEDIUM,
            owasp_llm=["LLM09"],
            owasp_agentic=["ASI07", "ASI08"],
            evidence=[
                Evidence(
                    type="network_capture",
                    summary=f"{len(outbound_lines)} outbound connections",
                    raw_data="\n".join(outbound_lines[:50]),
                    location=f"container:{cid}",
                ),
                Evidence(
                    type="config",
                    summary="Container network configuration",
                    raw_data=net_info[:2000],
                    location=f"container:{cid}",
                ),
            ],
            remediation=(
                "Restrict outbound network access using Docker network policies "
                "or iptables rules. Use an allow-list of required external "
                "endpoints. Consider running the container with --network=none "
                "and proxying only necessary traffic."
            ),
            cvss_score=5.3,
            ai_risk_score=6.0,
        )

    # ------------------------------------------------------------------
    # Source code grep helper
    # ------------------------------------------------------------------

    async def _grep_source(self, pattern: str) -> str:
        """Run a case-insensitive grep inside the container and return matches.

        Searches common application directories (/app, /src, /opt) for the
        given regex *pattern*.  Returns the raw ``grep`` output (file paths
        and matching lines) or an empty string when nothing is found or the
        container is unavailable.
        """
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                f"grep -r -i -l '{pattern}' /app /src /opt 2>/dev/null | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Model Theft & Extraction Detection (M3.5)
    # ------------------------------------------------------------------

    async def _check_model_extraction_defenses(self, info: dict[str, Any]) -> None:
        """Check for defenses against model theft and extraction attacks.

        Verifies the presence of rate limiting on inference endpoints,
        query logging/monitoring, and output perturbation techniques
        that make model extraction attacks harder to execute.
        """
        cid = self.context.container_id
        if not cid:
            return

        # --- Rate limiting on model inference endpoints ---
        rate_limit_hits = await self._grep_source(
            r"RateLimit\|rate_limit\|ratelimit\|throttle\|slowapi\|"
            r"token_bucket\|sliding_window"
        )
        if not rate_limit_hits:
            self.add_finding(
                title="No rate limiting detected on model inference endpoints",
                description=(
                    "No rate limiting mechanisms were found in the application "
                    "source code. Without rate limiting, an attacker can issue "
                    "a large number of queries to systematically extract or "
                    "replicate the model through prediction APIs. Model "
                    "extraction attacks typically require thousands of queries "
                    "that would be blocked by proper rate limits."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07", "ASI08"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No rate limiting patterns found in source",
                        raw_data="Searched for: RateLimit, rate_limit, ratelimit, "
                                 "throttle, slowapi, token_bucket, sliding_window",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Implement rate limiting on all model inference and prediction "
                    "endpoints. Use libraries such as SlowAPI (FastAPI), "
                    "flask-limiter, or a reverse proxy rate limiter (nginx, "
                    "Envoy). Set per-user and per-IP limits appropriate for "
                    "legitimate usage patterns."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "https://arxiv.org/abs/1609.02943",
                ],
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

        # --- Query logging / monitoring ---
        query_log_hits = await self._grep_source(
            r"inference_log\|prediction_log\|access_log\|audit_trail\|"
            r"request_counter\|usage_tracking\|query_monitor"
        )
        if not query_log_hits:
            self.add_finding(
                title="No inference query logging or monitoring detected",
                description=(
                    "No query logging or monitoring mechanisms were found for "
                    "model inference endpoints. Without logging, anomalous "
                    "query patterns indicative of model extraction attempts "
                    "(e.g., systematic exploration of the decision boundary) "
                    "will go undetected."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07", "ASI08"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No inference logging patterns found in source",
                        raw_data="Searched for: inference_log, prediction_log, "
                                 "access_log, audit_trail, request_counter, "
                                 "usage_tracking, query_monitor",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Add structured logging for all inference requests including "
                    "timestamps, user identity, input features, and response "
                    "metadata. Implement anomaly detection on query patterns to "
                    "identify potential extraction campaigns. Consider using an "
                    "audit trail system for compliance."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=5.3,
                ai_risk_score=6.0,
            )

        # --- Output perturbation / watermarking ---
        perturbation_hits = await self._grep_source(
            r"add_noise\|laplace_noise\|gaussian_noise\|output_perturbation\|"
            r"prediction_watermark\|differential_privacy\|dp_noise\|watermark"
        )
        if not perturbation_hits:
            self.add_finding(
                title="No output perturbation or watermarking detected",
                description=(
                    "No output perturbation or model watermarking techniques "
                    "were found. Adding calibrated noise to prediction outputs "
                    "or embedding watermarks can degrade the quality of "
                    "extracted model copies and help prove ownership of stolen "
                    "models. This is an advisory finding."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No output perturbation patterns found in source",
                        raw_data="Searched for: add_noise, laplace_noise, "
                                 "gaussian_noise, output_perturbation, "
                                 "prediction_watermark, differential_privacy, "
                                 "dp_noise, watermark",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Consider adding output perturbation (e.g., Laplace or "
                    "Gaussian noise calibrated to preserve utility) to model "
                    "predictions. Implement model watermarking to enable "
                    "detection of stolen model copies. Libraries such as "
                    "IBM ART or ML-Privacy-Meter can help."
                ),
                references=[
                    "https://arxiv.org/abs/1906.00830",
                    "https://arxiv.org/abs/1609.02943",
                ],
                cvss_score=2.0,
                ai_risk_score=3.0,
            )

    async def _check_model_api_security(self, info: dict[str, Any]) -> None:
        """Check model API endpoints for authentication and access control.

        Verifies that inference/prediction endpoints require authentication
        and that model versioning with access control is in place to prevent
        unauthorized access to model assets.
        """
        cid = self.context.container_id
        if not cid:
            return

        # --- API authentication on model endpoints ---
        auth_hits = await self._grep_source(
            r"api_key\|bearer_token\|jwt\|oauth\|authenticate\|"
            r"authorization\|auth_middleware\|requires_auth\|login_required"
        )
        if not auth_hits:
            self.add_finding(
                title="No API authentication detected on model endpoints",
                description=(
                    "No authentication mechanisms (API keys, JWT, OAuth, or "
                    "auth middleware) were found in the application source "
                    "code. Unauthenticated model endpoints allow any network "
                    "user to query the model freely, enabling model extraction, "
                    "abuse, and unauthorized use of compute resources."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07", "ASI08"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No authentication patterns found in source",
                        raw_data="Searched for: api_key, bearer_token, jwt, oauth, "
                                 "authenticate, authorization, auth_middleware, "
                                 "requires_auth, login_required",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Implement authentication on all model inference endpoints. "
                    "Use API keys, JWT tokens, or OAuth 2.0 depending on the "
                    "deployment context. Ensure that authentication is enforced "
                    "at the middleware level so it cannot be bypassed. Rotate "
                    "credentials regularly and implement key scoping."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                ],
                cvss_score=8.2,
                ai_risk_score=8.5,
            )

        # --- Model versioning and access control ---
        versioning_hits = await self._grep_source(
            r"model_registry\|model_version\|model_access\|access_control\|"
            r"model_catalog\|model_metadata\|model_permission\|rbac"
        )
        if not versioning_hits:
            self.add_finding(
                title="No model versioning or access control detected",
                description=(
                    "No model versioning, registry, or access control patterns "
                    "were found in the source code. Without proper model "
                    "versioning and access control, it is difficult to track "
                    "which model versions are deployed, who has access to them, "
                    "and whether deprecated or vulnerable models are still "
                    "being served."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07", "ASI08"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No model versioning/access control patterns found",
                        raw_data="Searched for: model_registry, model_version, "
                                 "model_access, access_control, model_catalog, "
                                 "model_metadata, model_permission, rbac",
                        location=f"container:{cid}",
                    )
                ],
                remediation=(
                    "Implement a model registry (e.g., MLflow, DVC, or a custom "
                    "registry) with versioning and role-based access control "
                    "(RBAC). Track model lineage, restrict who can deploy or "
                    "update models, and ensure deprecated models are properly "
                    "retired. Maintain an audit log of model access."
                ),
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                cvss_score=5.0,
                ai_risk_score=5.5,
            )
