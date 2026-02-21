"""Multi-Agent Cascade Analysis agent.

Analyses inter-agent/service dependencies, cascade failure risks,
authentication between services, trust boundaries, data poisoning
propagation, and message integrity in multi-agent architectures.
"""

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
# Compiled pattern groups used by the various checks
# ---------------------------------------------------------------------------
_P = re.compile  # shorthand

HEALTH_CHECK_PATTERNS = [
    _P(r"(?i)healthcheck"), _P(r"(?i)health[_\-]?check"), _P(r"(?i)/health\b"),
    _P(r"(?i)/ready\b"), _P(r"(?i)/liveness\b"), _P(r"(?i)livenessProbe"),
    _P(r"(?i)readinessProbe"),
]
CIRCUIT_BREAKER_PATTERNS = [
    _P(r"(?i)circuit[_\-\s]?breaker"), _P(r"(?i)pybreaker"),
    _P(r"(?i)resilience4j"), _P(r"(?i)hystrix"), _P(r"(?i)polly"),
    _P(r"(?i)tenacity"), _P(r"(?i)backoff\.on_exception"),
]
RETRY_TIMEOUT_PATTERNS = [
    _P(r"(?i)\bretry\b"), _P(r"(?i)\btimeout\b"), _P(r"(?i)max[_\-]?retries"),
    _P(r"(?i)retry[_\-]?policy"), _P(r"(?i)connect[_\-]?timeout"),
    _P(r"(?i)read[_\-]?timeout"), _P(r"(?i)deadline"),
]
FALLBACK_PATTERNS = [
    _P(r"(?i)\bfallback\b"), _P(r"(?i)graceful[_\-\s]?degrad"),
    _P(r"(?i)default[_\-]?response"), _P(r"(?i)failover"),
    _P(r"(?i)fail[_\-]?safe"), _P(r"(?i)backup[_\-]?service"),
]
AUTH_TOKEN_PATTERNS = [
    _P(r"(?i)Authorization\s*:"), _P(r"(?i)Bearer\s+"),
    _P(r"(?i)x[_\-]api[_\-]key"), _P(r"(?i)api[_\-]?token"),
    _P(r"(?i)auth[_\-]?header"), _P(r"(?i)\bjwt\b"), _P(r"(?i)\boauth\b"),
]
MTLS_PATTERNS = [
    _P(r"(?i)mutual[_\-\s]?tls"), _P(r"(?i)\bmtls\b"),
    _P(r"(?i)client[_\-]?cert"), _P(r"(?i)tls[_\-]?client[_\-]?auth"),
    _P(r"(?i)verify[_\-]?client"),
]
MESSAGE_SIGNING_PATTERNS = [
    _P(r"(?i)\bhmac\b"), _P(r"(?i)message[_\-\s]?sign"),
    _P(r"(?i)verify[_\-\s]?signature"), _P(r"(?i)digital[_\-\s]?signature"),
    _P(r"(?i)content[_\-]?hash"), _P(r"(?i)request[_\-]?signing"),
    _P(r"(?i)webhook[_\-]?secret"),
]
INTER_SERVICE_CALL_PATTERNS = [
    _P(r"(?i)requests\.(get|post|put|delete|patch)\s*\("),
    _P(r"(?i)httpx\.(get|post|put|delete|patch|AsyncClient)"),
    _P(r"(?i)aiohttp\.ClientSession"), _P(r"(?i)fetch\s*\("),
    _P(r"(?i)axios\.(get|post|put|delete|patch)"), _P(r"(?i)grpc\."),
    _P(r"(?i)urllib"),
]
INPUT_VALIDATION_PATTERNS = [
    _P(r"(?i)validate\s*\("), _P(r"(?i)pydantic"), _P(r"(?i)marshmallow"),
    _P(r"(?i)cerberus"), _P(r"(?i)json[_\-]?schema"), _P(r"(?i)sanitize"),
    _P(r"(?i)bleach"), _P(r"(?i)input[_\-]?validation"),
]
OUTPUT_SANITIZATION_PATTERNS = [
    _P(r"(?i)sanitize[_\-\s]?output"), _P(r"(?i)output[_\-\s]?filter"),
    _P(r"(?i)output[_\-\s]?validation"), _P(r"(?i)escape[_\-\s]?output"),
    _P(r"(?i)response[_\-\s]?filter"),
]
CORRELATION_PATTERNS = [
    _P(r"(?i)request[_\-]?id"), _P(r"(?i)correlation[_\-]?id"),
    _P(r"(?i)trace[_\-]?id"), _P(r"(?i)x[_\-]request[_\-]id"),
    _P(r"(?i)span[_\-]?id"), _P(r"(?i)opentelemetry"),
    _P(r"(?i)jaeger"), _P(r"(?i)zipkin"),
]
HMAC_SIGNATURE_PATTERNS = [
    _P(r"(?i)hmac\."), _P(r"(?i)hashlib\.sha256"), _P(r"(?i)createHmac"),
    _P(r"(?i)\bsign\s*\("), _P(r"(?i)\bverify\s*\("),
    _P(r"(?i)signature"), _P(r"(?i)digest\s*\("),
]
PLAINTEXT_COMM_PATTERNS = [
    _P(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"),
    _P(r"(?i)grpc\.insecure_channel"), _P(r"(?i)verify\s*=\s*False"),
    _P(r"(?i)ssl\s*=\s*False"), _P(r"(?i)tls\s*=\s*False"),
]

_SCAN_DIRS = "/app /src /opt /home /etc"
_ALL_EXTENSIONS = (
    "*.py *.js *.ts *.go *.java *.rs *.rb "
    "*.yaml *.yml *.toml *.ini *.cfg *.conf *.json *.env"
)


class CascadeAgent(BaseAgent):
    """Analyse multi-agent cascade risks, inter-service dependencies,
    trust boundaries, and message integrity."""

    name: ClassVar[str] = "cascade"
    description: ClassVar[str] = (
        "Analyses inter-agent/service dependency graphs, cascade failure "
        "scenarios, inter-service authentication, trust boundaries, data "
        "poisoning propagation paths, and message integrity controls."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["ASI08", "ASI07"]
    depends_on: ClassVar[list[str]] = ["permission", "network"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all cascade and inter-agent security checks."""
        file_contents = await self._collect_file_contents()
        compose_data = await self._load_compose_config()
        container_info = await self._get_container_info()

        await self._check_agent_dependency_graph(compose_data, file_contents)
        await self._check_cascade_failure_risk(compose_data, file_contents, container_info)
        await self._check_inter_agent_auth(file_contents, container_info)
        await self._check_trust_boundaries(compose_data, container_info, file_contents)
        await self._check_poisoning_propagation(file_contents, container_info)
        await self._check_message_integrity(file_contents, container_info)

    # ------------------------------------------------------------------
    # Container / Docker helpers
    # ------------------------------------------------------------------

    def _exec(self, cmd: str) -> tuple[int, str]:
        dm = self.context.docker_manager
        if dm is not None:
            return dm.exec_in_target(cmd)
        return 1, ""

    async def _get_container_info(self) -> dict[str, Any]:
        dm = self.context.docker_manager
        if dm is not None:
            try:
                return await asyncio.to_thread(dm.inspect_target)
            except Exception:
                logger.debug("docker_manager.inspect_target failed; trying CLI")
        cid = self.context.container_id
        if not cid:
            return {}
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", cid,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            data = json.loads(stdout)
            return data[0] if isinstance(data, list) else data
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # File collection helpers
    # ------------------------------------------------------------------

    async def _collect_file_contents(self) -> dict[str, str]:
        if not self.context.container_id and self.context.docker_manager is None:
            return {}
        ext_args = " -o ".join(f"-name '{e}'" for e in _ALL_EXTENSIONS.split())
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 5 -type f \\( {ext_args} \\) "
            f"-size -1024k 2>/dev/null | head -200"
        )
        try:
            rc, out = await asyncio.to_thread(self._exec, f"sh -c {find_cmd!r}")
            if rc != 0:
                return {}
            file_list = out.strip().splitlines()
        except Exception:
            return {}
        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                rc, data = await asyncio.to_thread(self._exec, f"head -c 65536 {fpath}")
                if rc == 0 and data:
                    contents[fpath] = data
            except Exception:
                continue
        return contents

    async def _load_compose_config(self) -> dict[str, Any]:
        if not self.context.container_id and self.context.docker_manager is None:
            return {}
        find_cmd = (
            f"find {_SCAN_DIRS} -maxdepth 4 -type f "
            "\\( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' "
            "-o -name 'compose.yml' -o -name 'compose.yaml' \\) "
            "2>/dev/null | head -5"
        )
        compose_paths: list[str] = []
        try:
            rc, out = await asyncio.to_thread(self._exec, f"sh -c {find_cmd!r}")
            if rc == 0 and out.strip():
                compose_paths = [p.strip() for p in out.strip().splitlines()]
        except Exception:
            pass
        compose_paths += [
            "/app/docker-compose.yml", "/app/docker-compose.yaml",
            "/app/compose.yml", "/src/docker-compose.yml",
            "/docker-compose.yml",
        ]
        for path in compose_paths:
            try:
                rc, content = await asyncio.to_thread(
                    self._exec, f"cat {path} 2>/dev/null",
                )
                if rc != 0 or not content.strip():
                    continue
                try:
                    import yaml  # type: ignore[import-untyped]
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        data["_raw_content"] = content
                        data["_source_path"] = path
                        return data
                except ImportError:
                    return {"_raw_content": content, "_source_path": path}
                except Exception:
                    return {"_raw_content": content, "_source_path": path}
            except Exception:
                continue
        return {}

    # ------------------------------------------------------------------
    # Pattern search helpers
    # ------------------------------------------------------------------

    def _search(self, files: dict[str, str], patterns: list[re.Pattern[str]]) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for fpath, content in files.items():
            for pat in patterns:
                for m in list(pat.finditer(content))[:3]:
                    s, e = max(0, m.start() - 40), min(len(content), m.end() + 60)
                    hits.append((fpath, content[s:e].strip().replace("\n", " ")))
        return hits

    def _has(self, files: dict[str, str], patterns: list[re.Pattern[str]]) -> bool:
        for content in files.values():
            for pat in patterns:
                if pat.search(content):
                    return True
        return False

    # ------------------------------------------------------------------
    # 1. Agent Dependency Graph Analysis
    # ------------------------------------------------------------------

    async def _check_agent_dependency_graph(
        self, compose: dict[str, Any], files: dict[str, str],
    ) -> None:
        dep_map: dict[str, list[str]] = {}
        raw = compose.get("_raw_content", "")
        services: dict[str, Any] = compose.get("services", {})

        if services and isinstance(services, dict):
            for svc, cfg in services.items():
                if not isinstance(cfg, dict):
                    continue
                deps: list[str] = []
                do = cfg.get("depends_on", [])
                if isinstance(do, list):
                    deps.extend(do)
                elif isinstance(do, dict):
                    deps.extend(do.keys())
                for link in (cfg.get("links") or []):
                    d = link.split(":")[0] if ":" in link else link
                    if d not in deps:
                        deps.append(d)
                env = cfg.get("environment", [])
                if isinstance(env, dict):
                    env = [f"{k}={v}" for k, v in env.items()]
                for e in (env if isinstance(env, list) else []):
                    for other in services:
                        if other != svc and other in str(e) and other not in deps:
                            deps.append(other)
                dep_map[svc] = deps
        elif raw:
            for m in re.finditer(
                r"(\w[\w\-]*?):\s*\n(?:.*\n)*?\s+depends_on:\s*\n((?:\s+-\s+\w[\w\-]*\n)+)",
                raw, re.MULTILINE,
            ):
                dep_map.setdefault(m.group(1), []).extend(
                    re.findall(r"-\s+(\w[\w\-]*)", m.group(2))
                )

        info = await self._get_container_info()
        for ev in (info.get("Config", {}).get("Env") or []):
            m = re.match(r"(?i)(\w+)[_\-](?:host|url|uri|endpoint|service)\s*=\s*(.+)", ev)
            if m:
                dep_map.setdefault("target", [])
                ref = m.group(1).lower()
                if ref not in dep_map["target"]:
                    dep_map["target"].append(ref)

        for fpath, content in files.items():
            if not any(fpath.endswith(x) for x in (".yaml", ".yml", ".json", ".toml", ".conf")):
                continue
            for ref in re.findall(
                r"(?i)(?:url|host|endpoint|service)[\"'\s:=]+[\"']?(?:https?://)?(\w[\w\-]*?)(?:[:\./\"'\s]|$)",
                content,
            ):
                if ref.lower() in ("localhost", "127", "true", "false", "null", "none") or len(ref) < 3:
                    continue
                dep_map.setdefault("target", [])
                if ref.lower() not in dep_map["target"]:
                    dep_map["target"].append(ref.lower())

        if not dep_map:
            return

        issues: list[tuple[str, str]] = []  # (type, desc)

        # Single-point-of-failure
        counts: dict[str, int] = {}
        for deps in dep_map.values():
            for d in deps:
                counts[d] = counts.get(d, 0) + 1
        for svc, cnt in counts.items():
            if cnt >= 2:
                issues.append(("spof", f"'{svc}' depended on by {cnt} services"))

        # Circular dependencies (DFS)
        visited: set[str] = set()
        rec: set[str] = set()
        path: list[str] = []
        cycles: list[str] = []

        def dfs(n: str) -> None:
            visited.add(n); rec.add(n); path.append(n)
            for nb in dep_map.get(n, []):
                if nb not in visited:
                    dfs(nb)
                elif nb in rec:
                    cycles.append(" -> ".join(path[path.index(nb):] + [nb]))
            path.pop(); rec.discard(n)

        for node in dep_map:
            if node not in visited:
                dfs(node)
        for c in cycles:
            issues.append(("cycle", f"Circular: {c}"))

        # Long chains (> 3 hops)
        def chains(n: str, ch: list[str], v: set[str]) -> None:
            if len(ch) > 4:
                issues.append(("chain", f"Long chain ({len(ch)-1} hops): {' -> '.join(ch)}"))
                return
            for nb in dep_map.get(n, []):
                if nb not in v:
                    v.add(nb); ch.append(nb)
                    chains(nb, ch, v)
                    ch.pop(); v.discard(nb)

        for start in dep_map:
            chains(start, [start], {start})

        dep_summary = "\n".join(f"  {s} -> [{', '.join(d)}]" for s, d in sorted(dep_map.items()))
        source = compose.get("_source_path", "container")

        if not issues:
            self.add_finding(
                title="Service dependency graph mapped",
                description=f"Identified {len(dep_map)} service(s). No structural issues detected.",
                severity=Severity.INFO, owasp_agentic=["ASI08"], nist_ai_rmf=["MAP"],
                evidence=[Evidence(type="config", summary=f"Dependency graph ({len(dep_map)} services)",
                                   raw_data=dep_summary, location=source)],
                remediation="Monitor the dependency graph as the architecture evolves.",
            )
            return

        spof = [d for t, d in issues if t == "spof"]
        cyc = [d for t, d in issues if t == "cycle"]
        chn = [d for t, d in issues if t == "chain"]

        if spof:
            self.add_finding(
                title=f"Single-point-of-failure services detected ({len(spof)})",
                description=f"Found {len(spof)} service(s) that are critical dependencies for multiple others. "
                            "Failure cascades to all dependents.",
                severity=Severity.HIGH, owasp_agentic=["ASI08"], nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[Evidence(type="config", summary="SPOF services",
                    raw_data="\n".join(f"  - {d}" for d in spof) + "\n\nGraph:\n" + dep_summary,
                    location=source)],
                remediation="Add redundancy via replicas, load balancers, or failover. Implement health checks.",
                cvss_score=7.0, ai_risk_score=8.0,
            )
        if cyc:
            self.add_finding(
                title=f"Circular dependencies detected ({len(cyc)})",
                description=f"Found {len(cyc)} circular dependency chain(s) creating deadlock and recovery risks.",
                severity=Severity.HIGH, owasp_agentic=["ASI08"], nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[Evidence(type="config", summary="Circular deps",
                    raw_data="\n".join(f"  - {d}" for d in cyc), location=source)],
                remediation="Break cycles with message queues or event buses. Use async communication.",
                cvss_score=6.5, ai_risk_score=7.5,
            )
        if chn:
            self.add_finding(
                title=f"Long dependency chains detected ({len(chn)})",
                description=f"Found {len(chn)} chain(s) exceeding 3 hops, amplifying latency and failure probability.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI08"], nist_ai_rmf=["MAP"],
                evidence=[Evidence(type="config", summary="Long chains",
                    raw_data="\n".join(f"  - {d}" for d in chn), location=source)],
                remediation="Flatten chains via direct paths or event buses. Add timeouts at each hop.",
                cvss_score=5.0, ai_risk_score=6.0,
            )

    # ------------------------------------------------------------------
    # 2. Cascade Failure Risk Assessment
    # ------------------------------------------------------------------

    async def _check_cascade_failure_risk(
        self, compose: dict[str, Any], files: dict[str, str], info: dict[str, Any],
    ) -> None:
        raw_compose = compose.get("_raw_content", "")
        compose_src = compose.get("_source_path", "")
        cid = self.context.container_id

        all_content: dict[str, str] = dict(files)
        if raw_compose:
            all_content["docker-compose.yml"] = raw_compose
        for extra in ("Dockerfile", "entrypoint.sh", "start.sh"):
            try:
                rc, c = await asyncio.to_thread(
                    self._exec, f"cat /app/{extra} 2>/dev/null || cat /src/{extra} 2>/dev/null")
                if rc == 0 and c.strip():
                    all_content[extra] = c
            except Exception:
                pass

        hc_cfg = info.get("Config", {}).get("Healthcheck")
        hc_compose = bool(re.search(r"(?i)healthcheck:", raw_compose)) if raw_compose else False

        if not hc_compose and hc_cfg is None and not self._has(all_content, HEALTH_CHECK_PATTERNS):
            self.add_finding(
                title="Missing health checks on dependent services",
                description="No health check configuration found in docker-compose, container config, or code. "
                            "Orchestrators cannot detect failures, leading to cascading outages.",
                severity=Severity.HIGH, owasp_agentic=["ASI08"], nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="config", summary="No health checks",
                    raw_data=f"compose: {compose_src or 'none'}, healthcheck: {json.dumps(hc_cfg)}, files: {len(files)}",
                    location=compose_src or f"container:{cid}")],
                remediation="Add GET /health endpoints. Configure healthcheck in docker-compose.yml with interval, "
                            "timeout, retries, and start_period. Use liveness/readiness probes in Kubernetes.",
                cvss_score=6.0, ai_risk_score=7.5,
            )

        if not self._has(all_content, CIRCUIT_BREAKER_PATTERNS):
            self.add_finding(
                title="No circuit breaker pattern detected",
                description="No circuit breaker found. Failing downstream services exhaust caller resources, "
                            "cascading failures system-wide.",
                severity=Severity.HIGH, owasp_agentic=["ASI08"], nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="file_content", summary="No circuit breakers",
                    raw_data=f"Searched {len(all_content)} files for circuit breaker patterns",
                    location=f"container:{cid}")],
                remediation="Use pybreaker, tenacity, resilience4j, or Hystrix. Configure failure thresholds "
                            "and recovery timeouts. Monitor breaker state transitions.",
                cvss_score=6.0, ai_risk_score=7.0,
            )

        if not self._has(all_content, RETRY_TIMEOUT_PATTERNS):
            self.add_finding(
                title="Missing retry and timeout configuration",
                description="No retry or timeout settings found. Requests to unresponsive services hang "
                            "indefinitely; transient errors propagate instead of being absorbed.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI08"], nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="file_content", summary="No retry/timeout config",
                    raw_data=f"Searched {len(all_content)} files", location=f"container:{cid}")],
                remediation="Set connect_timeout=5s, read_timeout=30s. Use exponential backoff with jitter "
                            "(max_retries=3, base_delay=1s). Retry only on transient 5xx errors.",
                cvss_score=5.0, ai_risk_score=6.0,
            )

        if not self._has(all_content, FALLBACK_PATTERNS):
            self.add_finding(
                title="Missing fallback and graceful degradation",
                description="No fallback patterns found. Any dependency failure causes complete outage "
                            "rather than degraded but functional operation.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI08"], nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="file_content", summary="No fallback patterns",
                    raw_data=f"Searched {len(all_content)} files", location=f"container:{cid}")],
                remediation="Implement cache-based fallbacks, default responses, failover routing, "
                            "and graceful feature degradation for each dependency.",
                cvss_score=4.5, ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 3. Inter-Agent Authentication
    # ------------------------------------------------------------------

    async def _check_inter_agent_auth(
        self, files: dict[str, str], info: dict[str, Any],
    ) -> None:
        call_hits = self._search(files, INTER_SERVICE_CALL_PATTERNS)
        if not call_hits:
            return
        call_files = {f for f, _ in call_hits}
        cid = self.context.container_id
        env_vars = info.get("Config", {}).get("Env") or []

        # 3a. Unauthenticated API calls
        auth_files = {f for f, _ in self._search(files, AUTH_TOKEN_PATTERNS)}
        unauth = call_files - auth_files
        if unauth:
            self.add_finding(
                title=f"API calls without authentication ({len(unauth)} files)",
                description=f"{len(unauth)} file(s) make inter-service calls without auth tokens "
                            "(Bearer, API key, JWT, OAuth). Rogue agents can impersonate services.",
                severity=Severity.HIGH, owasp_agentic=["ASI07", "ASI08"], owasp_llm=["LLM06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[Evidence(type="file_content", summary="Unauthenticated calls",
                    raw_data="\n".join(f"  - {f}" for f in sorted(unauth)[:20]),
                    location=f"container:{cid}")],
                remediation="Add JWT/API-key auth to all inter-service calls. Use mTLS or a service mesh.",
                cvss_score=7.5, ai_risk_score=8.0,
            )

        # 3b. Missing mTLS
        has_mtls = bool(self._search(files, MTLS_PATTERNS)) or any(
            any(k in str(e).lower() for k in ("mtls", "mutual_tls", "client_cert")) for e in env_vars
        )
        if not has_mtls:
            self.add_finding(
                title="Missing mutual TLS (mTLS) between services",
                description="No mTLS detected. One-way TLS does not verify caller identity; "
                            "network-level attackers can impersonate any service.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI07"], nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(type="config", summary="No mTLS",
                    raw_data=f"Searched {len(files)} files and {len(env_vars)} env vars",
                    location=f"container:{cid}")],
                remediation="Deploy mTLS via a service mesh (Istio, Linkerd) or configure client certificates "
                            "per service signed by an internal CA.",
                cvss_score=6.0, ai_risk_score=6.5,
            )

        # 3c. Shared secrets
        secret_re = re.compile(r"(?i)(?:shared[_\-]?secret|common[_\-]?key|global[_\-]?token|"
                               r"master[_\-]?key|universal[_\-]?password)")
        shared_hits: list[tuple[str, str]] = []
        for fp, content in files.items():
            for m in list(secret_re.finditer(content))[:3]:
                s, e = max(0, m.start()-30), min(len(content), m.end()+50)
                shared_hits.append((fp, content[s:e].strip().replace("\n", " ")))
        for ev in env_vars:
            if secret_re.search(str(ev)):
                shared_hits.append(("ENV", str(ev).split("=")[0]))
        if shared_hits:
            self.add_finding(
                title=f"Shared secrets across services ({len(shared_hits)} instances)",
                description="Shared secrets (shared_secret, master_key, etc.) mean one compromise exposes all.",
                severity=Severity.HIGH, owasp_agentic=["ASI07", "ASI08"], owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(type="file_content", summary="Shared secrets",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in shared_hits[:15]),
                    location=f"container:{cid}")],
                remediation="Issue per-service credentials via a secrets manager. Use mTLS for identity.",
                cvss_score=7.0, ai_risk_score=7.5,
            )

        # 3d. Missing message signing
        if not self._search(files, MESSAGE_SIGNING_PATTERNS):
            self.add_finding(
                title="Missing message signing/verification between services",
                description="Inter-service calls detected but no HMAC, signatures, or content hashing found. "
                            "Network attackers can tamper with messages between agents.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI07"], nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(type="file_content", summary="No signing",
                    raw_data=f"{len(call_hits)} calls in {len(call_files)} files, no signing patterns",
                    location=f"container:{cid}")],
                remediation="Add HMAC-SHA256 with timestamps on all inter-service messages to prevent "
                            "tampering and replay attacks.",
                cvss_score=5.5, ai_risk_score=6.0,
            )

    # ------------------------------------------------------------------
    # 4. Trust Boundary Analysis
    # ------------------------------------------------------------------

    async def _check_trust_boundaries(
        self, compose: dict[str, Any], info: dict[str, Any], files: dict[str, str],
    ) -> None:
        raw = compose.get("_raw_content", "")
        services: dict[str, Any] = compose.get("services", {})
        cid = self.context.container_id

        # 4a. Shared networks
        net_map: dict[str, list[str]] = {}
        if services and isinstance(services, dict):
            for svc, cfg in services.items():
                if not isinstance(cfg, dict):
                    continue
                nets = cfg.get("networks", [])
                if isinstance(nets, list):
                    for n in nets:
                        net_map.setdefault(str(n), []).append(svc)
                elif isinstance(nets, dict):
                    for n in nets:
                        net_map.setdefault(str(n), []).append(svc)
                else:
                    net_map.setdefault("default", []).append(svc)
            if not net_map and services:
                net_map["default"] = list(services.keys())
        elif raw:
            svc_names = re.findall(r"^\s{2}(\w[\w\-]*):\s*$", raw, re.MULTILINE)
            if len(svc_names) > 1 and len(re.findall(r"(?i)networks:", raw)) <= 1:
                net_map["default"] = svc_names

        for net_name in (info.get("NetworkSettings", {}).get("Networks") or {}):
            net_map.setdefault(net_name, []).append("target")

        flat = {n: s for n, s in net_map.items() if len(s) > 1}
        if flat:
            details = "\n".join(f"  Network '{n}': {', '.join(s)}" for n, s in flat.items())
            total = sum(len(s) for s in flat.values())
            self.add_finding(
                title=f"Services share network without micro-segmentation ({total} services)",
                description="Multiple services share network segments. A compromised agent can reach "
                            "all peers without crossing any network boundary.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI07", "ASI08"],
                nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[Evidence(type="config", summary="Shared networks", raw_data=details,
                    location=compose.get("_source_path", f"container:{cid}"))],
                remediation="Place each service tier on its own Docker network. Use network policies for ACLs.",
                cvss_score=5.0, ai_risk_score=6.0,
            )

        # 4b. Privileged on shared networks
        priv: list[str] = []
        if services and isinstance(services, dict):
            for svc, cfg in services.items():
                if not isinstance(cfg, dict):
                    continue
                caps = cfg.get("cap_add", [])
                if cfg.get("privileged") or (isinstance(caps, list) and any(
                    c.upper() in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL") for c in caps
                )):
                    priv.append(svc)
        hc = info.get("HostConfig", {})
        if hc.get("Privileged") or any(
            c.upper() in ("SYS_ADMIN", "NET_ADMIN", "ALL") for c in (hc.get("CapAdd") or [])
        ):
            priv.append("target")

        exposed = []
        for svc in priv:
            for net, members in flat.items():
                if svc in members:
                    others = [m for m in members if m != svc]
                    if others:
                        exposed.append(f"'{svc}' (privileged) shares '{net}' with: {', '.join(others)}")
        if exposed:
            self.add_finding(
                title=f"Privileged services on shared networks ({len(exposed)})",
                description="Privileged services share networks with unprivileged ones, enabling "
                            "lateral movement to host-level access.",
                severity=Severity.HIGH, owasp_agentic=["ASI07", "ASI08"], owasp_llm=["LLM06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[Evidence(type="config", summary="Privileged on shared nets",
                    raw_data="\n".join(f"  - {e}" for e in exposed),
                    location=compose.get("_source_path", f"container:{cid}"))],
                remediation="Isolate privileged services on dedicated networks. Remove privileged mode where possible.",
                cvss_score=8.0, ai_risk_score=8.5,
            )

        # 4c. Missing input validation at boundaries
        call_f = {f for f, _ in self._search(files, INTER_SERVICE_CALL_PATTERNS)}
        val_f = {f for f, _ in self._search(files, INPUT_VALIDATION_PATTERNS)}
        unval = call_f - val_f
        if unval:
            self.add_finding(
                title=f"Missing input validation at service boundaries ({len(unval)} files)",
                description=f"{len(unval)} file(s) with inter-service calls lack input validation. "
                            "Malformed data from compromised agents propagates unchecked.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI07", "ASI08"], nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="file_content", summary="Unvalidated boundaries",
                    raw_data="\n".join(f"  - {f}" for f in sorted(unval)[:20]),
                    location=f"container:{cid}")],
                remediation="Use pydantic/marshmallow/JSON Schema at every boundary. Validate types, ranges, sizes.",
                cvss_score=5.5, ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 5. Poisoning Propagation Analysis
    # ------------------------------------------------------------------

    async def _check_poisoning_propagation(
        self, files: dict[str, str], info: dict[str, Any],
    ) -> None:
        cid = self.context.container_id
        recv_re = re.compile(r"(?i)(?:request\.json|request\.data|request\.body|"
                             r"response\.json\(\)|response\.text|response\.content|"
                             r"message\.body|event\.data|payload|msg\.data)")
        fwd_re = re.compile(r"(?i)(?:requests\.post|httpx\.post|\.send\(|\.publish\(|"
                            r"\.emit\(|\.forward\(|\.dispatch\(|\.produce\()")

        # 5a. Data forwarded without validation
        fwd_files: list[str] = []
        for fp, content in files.items():
            if recv_re.search(content) and fwd_re.search(content):
                if not any(p.search(content) for p in INPUT_VALIDATION_PATTERNS):
                    fwd_files.append(fp)
        if fwd_files:
            self.add_finding(
                title=f"Data forwarded between services without validation ({len(fwd_files)} files)",
                description="Files receive data and forward it without validation, creating poisoning "
                            "propagation paths for prompt injection and data poisoning attacks.",
                severity=Severity.HIGH, owasp_agentic=["ASI08", "ASI07"], owasp_llm=["LLM04"],
                nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[Evidence(type="file_content", summary="Unvalidated forwarding",
                    raw_data="\n".join(f"  - {f}" for f in sorted(fwd_files)[:20]),
                    location=f"container:{cid}")],
                remediation="Validate and sanitize data at every boundary. Use schema validation before "
                            "forwarding. Implement content-based security filters.",
                cvss_score=7.0, ai_risk_score=8.0,
            )

        # 5b. Missing output sanitization
        if self._has(files, INTER_SERVICE_CALL_PATTERNS) and not self._has(files, OUTPUT_SANITIZATION_PATTERNS):
            self.add_finding(
                title="Missing output sanitization between agent boundaries",
                description="Inter-service calls detected but no output sanitization. Compromised agents "
                            "can propagate XSS, SQLi, or prompt injection payloads downstream.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI07", "ASI08"], owasp_llm=["LLM05"],
                nist_ai_rmf=["MANAGE"],
                evidence=[Evidence(type="file_content", summary="No output sanitization",
                    raw_data=f"Searched {len(files)} files", location=f"container:{cid}")],
                remediation="Sanitize all outgoing data. Use context-appropriate encoding (HTML, SQL params). "
                            "Define content policies per agent.",
                cvss_score=5.5, ai_risk_score=7.0,
            )

        # 5c. Shared data stores
        store_re = re.compile(r"(?i)(?:redis|memcached|mongodb|postgres|mysql|sqlite|elasticsearch|"
                              r"dynamodb|s3://|gcs://|shared[_\-]?volume|shared[_\-]?cache|"
                              r"shared[_\-]?database|shared[_\-]?state)")
        store_hits: list[tuple[str, str]] = []
        for fp, content in files.items():
            for m in list(store_re.finditer(content))[:5]:
                s, e = max(0, m.start()-30), min(len(content), m.end()+50)
                store_hits.append((fp, content[s:e].strip().replace("\n", " ")))
        env_store_re = re.compile(r"(?i)(?:redis|mongo|postgres|mysql|database|cache|store)"
                                  r"[_\-]?(?:url|host|uri|dsn)")
        for ev in (info.get("Config", {}).get("Env") or []):
            if env_store_re.search(str(ev)):
                store_hits.append(("ENV", str(ev).split("=")[0]))
        if store_hits:
            self.add_finding(
                title=f"Shared data stores accessible by multiple agents ({len(store_hits)} refs)",
                description="Shared stores (DBs, caches) create poisoning vectors: tainted writes "
                            "by one agent affect all readers.",
                severity=Severity.MEDIUM, owasp_agentic=["ASI08", "ASI07"], owasp_llm=["LLM04"],
                nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[Evidence(type="config", summary="Shared stores",
                    raw_data="\n".join(f"  - {f}: {s[:80]}" for f, s in store_hits[:20]),
                    location=f"container:{cid}")],
                remediation="Isolate stores per agent. Use separate DB users/schemas. Validate data on read. "
                            "Add audit trails and integrity checksums.",
                cvss_score=5.0, ai_risk_score=7.0,
            )

    # ------------------------------------------------------------------
    # 6. Message Integrity Checks
    # ------------------------------------------------------------------

    async def _check_message_integrity(
        self, files: dict[str, str], info: dict[str, Any],
    ) -> None:
        if not self._has(files, INTER_SERVICE_CALL_PATTERNS):
            return
        cid = self.context.container_id

        # 6a. Missing HMAC/signatures
        if not self._has(files, HMAC_SIGNATURE_PATTERNS):
            self.add_finding(
                title="Missing HMAC/signatures on inter-service messages",
                description="No HMAC or cryptographic signatures found. Network attackers can modify "
                            "messages between agents without detection (MITM).",
                severity=Severity.HIGH, owasp_agentic=["ASI07"], nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(type="file_content", summary="No HMAC/signatures",
                    raw_data=f"Searched {len(files)} files", location=f"container:{cid}")],
                remediation="Add HMAC-SHA256 with timestamps on all messages. Use per-service-pair keys. "
                            "Reject messages with stale timestamps (>5 min).",
                cvss_score=7.0, ai_risk_score=7.5,
            )

        # 6b. Unencrypted communication
        pt_hits = self._search(files, PLAINTEXT_COMM_PATTERNS)
        if pt_hits:
            self.add_finding(
                title=f"Unencrypted inter-service communication ({len(pt_hits)} instances)",
                description=f"{len(pt_hits)} instances of plaintext HTTP, insecure gRPC, or disabled TLS. "
                            "Exposes prompts, credentials, and model outputs to eavesdropping.",
                severity=Severity.HIGH, owasp_agentic=["ASI07"], owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[Evidence(type="file_content", summary="Plaintext comms",
                    raw_data="\n".join(f"  - {f}: {s[:100]}" for f, s in pt_hits[:20]),
                    location=f"container:{cid}")],
                remediation="Use TLS 1.2+ everywhere. Replace http:// with https://. Never set verify=False "
                            "in production. Use a service mesh for automatic encryption.",
                cvss_score=7.5, ai_risk_score=7.0,
            )

        # 6c. Missing correlation tracking
        if not self._has(files, CORRELATION_PATTERNS):
            self.add_finding(
                title="Missing request ID and correlation tracking",
                description="No request_id, correlation_id, or distributed tracing found. Cannot trace "
                            "malicious requests across agents, hampering incident response.",
                severity=Severity.LOW, owasp_agentic=["ASI08"], nist_ai_rmf=["MEASURE"],
                evidence=[Evidence(type="file_content", summary="No correlation tracking",
                    raw_data=f"Searched {len(files)} files", location=f"container:{cid}")],
                remediation="Deploy OpenTelemetry/Jaeger/Zipkin. Propagate X-Request-ID through all calls. "
                            "Log request_id with every entry for end-to-end tracing.",
                cvss_score=3.0, ai_risk_score=5.0,
            )
