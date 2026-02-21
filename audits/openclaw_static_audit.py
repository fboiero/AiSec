"""Static security audit of OpenClaw AI agent.

This script analyses the OpenClaw codebase at a given path without requiring
Docker, using AiSec's models, scoring, and reporting infrastructure.

Usage:
    python audits/openclaw_static_audit.py [--openclaw-path /path/to/OpenClaw]
"""

from __future__ import annotations

import json
import re
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

# Ensure AiSec src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aisec import __version__
from aisec.core.enums import Severity
from aisec.core.models import (
    AgentResult,
    ComplianceChecklist,
    ComplianceReport,
    Evidence,
    ExecutiveSummary,
    Finding,
    RiskOverview,
    ScanReport,
)
from aisec.reports.renderers import html_renderer, json_renderer
from aisec.utils.crypto import SECRET_PATTERNS, PII_PATTERNS


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_OPENCLAW_PATH = Path("/Users/fboiero/Documents/GitHub/OpenClaw")

# File patterns to scan
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".sh", ".bash", ".md", ".txt", ".csv", ".html", ".xml",
}

# Paths to skip (relative to OpenClaw root)
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "workspace",  # Agent runtime data (may contain locked files)
}

# Docker security patterns
DOCKER_SOCKET_MOUNT = re.compile(r"/var/run/docker\.sock")
PRIVILEGED_MODE = re.compile(r"privileged:\s*true", re.IGNORECASE)
USER_ROOT = re.compile(r"user:\s*root", re.IGNORECASE)
LATEST_TAG = re.compile(r"image:\s*\S+:latest", re.IGNORECASE)
BIND_ALL = re.compile(r'--bind.*(?:0\.0\.0\.0|lan)', re.IGNORECASE)

# Sensitive file patterns
ENV_FILE_PATTERN = re.compile(r"\.env$")
KEY_FILE_PATTERN = re.compile(r"\.(pem|key|p12|pfx|jks)$")

# Code execution patterns
DANGEROUS_CODE = [
    (re.compile(r"\beval\s*\("), "eval()", "CRITICAL"),
    (re.compile(r"\bexec\s*\("), "exec()", "CRITICAL"),
    (re.compile(r"subprocess\..*shell\s*=\s*True"), "subprocess with shell=True", "HIGH"),
    (re.compile(r"os\.system\s*\("), "os.system()", "HIGH"),
    (re.compile(r"os\.popen\s*\("), "os.popen()", "HIGH"),
    (re.compile(r"__import__\s*\("), "__import__()", "MEDIUM"),
]


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

class _ReadTimeout(Exception):
    """Raised when a file read times out."""


def _timeout_handler(signum: int, frame: Any) -> None:
    raise _ReadTimeout()


def collect_files(root: Path) -> dict[str, str]:
    """Recursively collect text file contents from the target."""
    files: dict[str, str] = {}
    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        # Skip very large files
        try:
            if path.stat().st_size > 1_000_000:
                continue
            # Use alarm-based timeout to avoid blocking on locked files
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(2)  # 2 second timeout per file
            try:
                content = path.read_text(errors="replace")
                signal.alarm(0)
            except _ReadTimeout:
                signal.alarm(0)
                continue
            finally:
                signal.signal(signal.SIGALRM, old_handler)
            files[str(path.relative_to(root))] = content
        except (PermissionError, OSError):
            continue
    return files


# ---------------------------------------------------------------------------
# Audit checks
# ---------------------------------------------------------------------------

def check_secrets(files: dict[str, str]) -> list[Finding]:
    """Scan all files for hardcoded secrets."""
    findings: list[Finding] = []
    secret_hits: dict[str, list[tuple[str, str]]] = {}

    for fpath, content in files.items():
        for name, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                for m in matches[:3]:
                    val = str(m)
                    # Mask values
                    masked = val[:6] + "****" + val[-4:] if len(val) > 14 else val[:4] + "****"
                    secret_hits.setdefault(name, []).append((fpath, masked))

    for secret_name, hits in secret_hits.items():
        severity = Severity.CRITICAL if secret_name in (
            "aws_access_key", "aws_secret_key", "private_key",
            "openai_key", "anthropic_key", "github_token",
            "stripe_key", "database_url",
        ) else Severity.HIGH

        evidence_lines = [f"  {f}: {v}" for f, v in hits[:15]]
        findings.append(Finding(
            title=f"Hardcoded secret: {secret_name} ({len(hits)} occurrences)",
            description=(
                f"Found {len(hits)} instance(s) of '{secret_name}' pattern in the "
                f"OpenClaw codebase. Hardcoded secrets can be extracted by anyone "
                f"with filesystem access or from Docker image layers."
            ),
            severity=severity,
            agent="static_audit",
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI04"],
            nist_ai_rmf=["GOVERN"],
            evidence=[Evidence(
                type="file_content",
                summary=f"{secret_name} ({len(hits)} hits)",
                raw_data="\n".join(evidence_lines),
                location="openclaw_codebase",
            )],
            remediation=(
                "Remove hardcoded secrets from configuration files. Use environment "
                "variables injected at runtime, Docker secrets, or a secrets manager "
                "(e.g., HashiCorp Vault). Rotate all exposed credentials immediately."
            ),
            cvss_score=9.0 if severity == Severity.CRITICAL else 7.5,
            ai_risk_score=8.5,
        ))

    return findings


def check_pii(files: dict[str, str]) -> list[Finding]:
    """Scan for PII patterns in code and config files."""
    findings: list[Finding] = []
    pii_hits: dict[str, list[tuple[str, str]]] = {}

    # Only scan config/data files, not code that defines PII patterns
    config_extensions = {".json", ".yaml", ".yml", ".env", ".md", ".txt", ".csv"}
    for fpath, content in files.items():
        if not any(fpath.endswith(ext) for ext in config_extensions):
            continue
        for name, pattern in PII_PATTERNS.items():
            matches = pattern.findall(content)
            if matches and len(matches) < 50:  # Skip noisy patterns
                for m in matches[:3]:
                    val = str(m)
                    masked = val[:3] + "***" if len(val) > 3 else "***"
                    pii_hits.setdefault(name, []).append((fpath, masked))

    for pii_name, hits in pii_hits.items():
        if pii_name in ("phone_international", "passport"):
            continue  # Too many false positives

        evidence_lines = [f"  {f}: {v}" for f, v in hits[:10]]
        findings.append(Finding(
            title=f"PII detected: {pii_name} ({len(hits)} occurrences)",
            description=(
                f"Found {len(hits)} instance(s) of '{pii_name}' pattern in "
                f"configuration and data files."
            ),
            severity=Severity.MEDIUM,
            agent="static_audit",
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN", "MAP"],
            evidence=[Evidence(
                type="file_content",
                summary=f"{pii_name} ({len(hits)} hits)",
                raw_data="\n".join(evidence_lines),
                location="openclaw_codebase",
            )],
            remediation=(
                "Remove or encrypt PII data. Implement data minimization "
                "practices. Use tokenization or pseudonymization."
            ),
            cvss_score=5.5,
            ai_risk_score=6.0,
        ))

    return findings


def check_docker_security(root: Path, files: dict[str, str]) -> list[Finding]:
    """Analyze Docker configuration for security issues."""
    findings: list[Finding] = []

    # Check docker-compose.yml
    compose_files = [f for f in files if "docker-compose" in f.lower()]
    for fpath in compose_files:
        content = files[fpath]

        # Docker socket mount
        if DOCKER_SOCKET_MOUNT.search(content):
            findings.append(Finding(
                title="Docker socket mounted into container",
                description=(
                    "The Docker socket (/var/run/docker.sock) is mounted into "
                    "the container. This grants the container full control over "
                    "the Docker daemon, which is equivalent to root access on "
                    "the host. Any code execution inside the container (including "
                    "agent-generated code) can escape the container boundary."
                ),
                severity=Severity.CRITICAL,
                agent="static_audit",
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI05"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[Evidence(
                    type="config",
                    summary="Docker socket volume mount",
                    raw_data="- /var/run/docker.sock:/var/run/docker.sock",
                    location=fpath,
                )],
                remediation=(
                    "Use rootless Docker or an isolated Docker daemon instead "
                    "of mounting the host Docker socket. Consider using gVisor "
                    "or Kata Containers for stronger isolation. If Docker-in-Docker "
                    "is required, use 'docker:dind' with TLS authentication."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
                cvss_score=9.8,
                ai_risk_score=9.5,
            ))

        # Running as root
        if USER_ROOT.search(content):
            findings.append(Finding(
                title="Container runs as root user",
                description=(
                    "The container is configured with 'user: root'. Combined "
                    "with the Docker socket mount, this provides unrestricted "
                    "host root access. The agent can create privileged containers, "
                    "access all host files, and execute arbitrary host commands."
                ),
                severity=Severity.CRITICAL,
                agent="static_audit",
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI03"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="config",
                    summary="Root user in container",
                    raw_data="user: root",
                    location=fpath,
                )],
                remediation=(
                    "Run the container as a non-root user. Create a dedicated "
                    "user in the Dockerfile with minimal privileges. Use "
                    "'user: 1000:1000' or similar in docker-compose.yml."
                ),
                cvss_score=8.5,
                ai_risk_score=9.0,
            ))

        # Unpinned image tag
        if LATEST_TAG.search(content):
            findings.append(Finding(
                title="Docker image uses unpinned :latest tag",
                description=(
                    "The Docker image uses the ':latest' tag which is mutable. "
                    "An attacker who compromises the image registry can push a "
                    "malicious image that will be automatically pulled."
                ),
                severity=Severity.MEDIUM,
                agent="static_audit",
                owasp_llm=["LLM03"],
                owasp_agentic=["ASI04"],
                nist_ai_rmf=["MAP"],
                evidence=[Evidence(
                    type="config",
                    summary="Mutable image tag",
                    raw_data="image: alpine/openclaw:latest",
                    location=fpath,
                )],
                remediation=(
                    "Pin Docker images to a specific digest: "
                    "'alpine/openclaw@sha256:abc123...'. Use automated tools "
                    "like Renovate or Dependabot to update digests."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            ))

        # Gateway binds to LAN
        if BIND_ALL.search(content):
            findings.append(Finding(
                title="Gateway binds to LAN interface",
                description=(
                    "The gateway process is started with '--bind lan', listening "
                    "on all container interfaces. While the Docker port mapping "
                    "binds to 127.0.0.1, any misconfiguration or Docker network "
                    "access would expose the gateway to the network."
                ),
                severity=Severity.MEDIUM,
                agent="static_audit",
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[Evidence(
                    type="config",
                    summary="LAN bind directive",
                    raw_data='command: --bind lan',
                    location=fpath,
                )],
                remediation=(
                    "Bind the gateway to localhost (127.0.0.1) inside the "
                    "container as well, not just in the Docker port mapping."
                ),
                cvss_score=4.5,
                ai_risk_score=5.0,
            ))

    return findings


def check_agent_permissions(files: dict[str, str]) -> list[Finding]:
    """Analyze agent permission model for excessive agency."""
    findings: list[Finding] = []

    # Look for openclaw.json with tool permissions
    for fpath, content in files.items():
        if "openclaw.json" not in fpath or ".bak" in fpath:
            continue
        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            continue

        # Check tool permissions
        tools = config.get("tools", {})
        allowed = tools.get("allow", [])
        denied = tools.get("deny", [])

        dangerous_tools = {"process", "browser", "cron"}
        allowed_dangerous = [t for t in allowed if t in dangerous_tools]

        if allowed_dangerous:
            findings.append(Finding(
                title=f"Agent has access to dangerous tools: {', '.join(allowed_dangerous)}",
                description=(
                    f"The AI agent has access to {len(allowed_dangerous)} potentially "
                    f"dangerous tool(s): {', '.join(allowed_dangerous)}. The 'process' "
                    f"tool enables arbitrary shell command execution. Combined with "
                    f"Docker socket access, this allows full host compromise."
                ),
                severity=Severity.HIGH,
                agent="static_audit",
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI05"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[Evidence(
                    type="config",
                    summary="Dangerous tools allowed",
                    raw_data=json.dumps(tools, indent=2),
                    location=fpath,
                )],
                remediation=(
                    "Apply the principle of least privilege. Restrict the 'process' "
                    "tool to a whitelist of safe commands. Require human confirmation "
                    "for destructive operations. Use a sandboxed execution environment "
                    "without Docker socket access."
                ),
                cvss_score=8.0,
                ai_risk_score=8.5,
            ))

        # Check sandbox configuration
        sandbox = config.get("sandbox", {})
        if sandbox.get("mode") == "all" and sandbox.get("workspaceAccess") == "rw":
            findings.append(Finding(
                title="Agent sandbox grants full read-write workspace access",
                description=(
                    "The agent sandbox is configured with mode='all' and "
                    "workspaceAccess='rw', granting the agent unrestricted "
                    "read-write access to the entire workspace directory. This "
                    "allows the agent to modify its own instructions, memory "
                    "files, and configuration."
                ),
                severity=Severity.MEDIUM,
                agent="static_audit",
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="config",
                    summary="Unrestricted sandbox access",
                    raw_data=json.dumps(sandbox, indent=2),
                    location=fpath,
                )],
                remediation=(
                    "Restrict workspace access to 'ro' (read-only) by default. "
                    "Use fine-grained path-based permissions to control which "
                    "directories the agent can write to."
                ),
                cvss_score=5.5,
                ai_risk_score=7.0,
            ))

    return findings


def check_memory_security(files: dict[str, str]) -> list[Finding]:
    """Check agent memory system for security risks."""
    findings: list[Finding] = []

    # Look for memory files
    memory_files = [f for f in files if "memory" in f.lower() or "SOUL" in f or "USER" in f]
    if memory_files:
        findings.append(Finding(
            title="Agent memory stored as plaintext files",
            description=(
                f"Found {len(memory_files)} agent memory/context file(s) stored "
                f"as plaintext on the filesystem. These files accumulate personal "
                f"context about the user over time and are readable by any process "
                f"with filesystem access. Memory files: "
                + ", ".join(memory_files[:10])
            ),
            severity=Severity.MEDIUM,
            agent="static_audit",
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN"],
            evidence=[Evidence(
                type="file_content",
                summary=f"{len(memory_files)} memory files",
                raw_data="\n".join(f"  {f}" for f in memory_files[:20]),
                location="openclaw_codebase",
            )],
            remediation=(
                "Encrypt memory files at rest. Implement access controls "
                "so only the agent process can read its memory. Add a data "
                "retention policy to purge old memory entries."
            ),
            cvss_score=4.0,
            ai_risk_score=6.5,
        ))

    return findings


def check_data_retention(files: dict[str, str]) -> list[Finding]:
    """Check for data retention policy."""
    findings: list[Finding] = []

    retention_pattern = re.compile(
        r"(?i)(?:retention|ttl|expir[ey]|max[_\-]?age|purge|cleanup[_\-]?after"
        r"|delete[_\-]?after|keep[_\-]?days|log[_\-]?rotation)",
    )

    config_files = [f for f in files if any(f.endswith(ext) for ext in (".json", ".yaml", ".yml", ".conf", ".env"))]
    has_retention = any(retention_pattern.search(files[f]) for f in config_files)

    if not has_retention:
        # Check for session files
        session_files = [f for f in files if "session" in f.lower() and f.endswith(".jsonl")]
        findings.append(Finding(
            title="No data retention policy detected",
            description=(
                f"No retention, TTL, or expiry settings found in "
                f"{len(config_files)} configuration file(s). Session files "
                f"and conversation history accumulate indefinitely without "
                f"rotation or archival. This may violate GDPR, CCPA, and "
                f"other data protection regulations."
            ),
            severity=Severity.MEDIUM,
            agent="static_audit",
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
            nist_ai_rmf=["GOVERN"],
            evidence=[Evidence(
                type="config",
                summary="No retention policy found",
                raw_data=f"Config files scanned: {len(config_files)}, Session files found: {len(session_files)}",
                location="openclaw_codebase",
            )],
            remediation=(
                "Implement a data retention policy. Set TTL values for "
                "session transcripts, conversation logs, and memory files. "
                "Automate purging of expired data."
            ),
            cvss_score=4.0,
            ai_risk_score=5.5,
        ))

    return findings


def check_skill_security(files: dict[str, str]) -> list[Finding]:
    """Check skill system for security risks."""
    findings: list[Finding] = []

    skill_files = [f for f in files if "skills" in f.lower() and f.endswith(".md")]

    # Check for elevated execution
    elevated_skills = []
    for fpath in skill_files:
        content = files[fpath]
        if "elevated" in content.lower():
            elevated_skills.append(fpath)

    if elevated_skills:
        findings.append(Finding(
            title=f"Skills with host-level execution capability ({len(elevated_skills)} skills)",
            description=(
                "Skills with 'elevated: true' capability can bypass the "
                "Docker sandbox and execute directly on the host. This is "
                "a documented escape hatch that could be triggered by "
                "prompt injection via any input channel."
            ),
            severity=Severity.HIGH,
            agent="static_audit",
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI02", "ASI05"],
            nist_ai_rmf=["GOVERN"],
            evidence=[Evidence(
                type="file_content",
                summary=f"{len(elevated_skills)} skills with elevated access",
                raw_data="\n".join(f"  {f}" for f in elevated_skills),
                location="openclaw_codebase",
            )],
            remediation=(
                "Remove the 'elevated' parameter from skills or require "
                "explicit per-use user approval. Implement a strict whitelist "
                "of commands that can run elevated."
            ),
            cvss_score=7.5,
            ai_risk_score=8.0,
        ))

    # Check for dangerous skill capabilities
    dangerous_capabilities = ["camera", "imessage", "whatsapp", "peekaboo", "screen", "ui automation"]
    dangerous_found = []
    for fpath in skill_files:
        content = files[fpath].lower()
        for cap in dangerous_capabilities:
            if cap in content:
                dangerous_found.append((fpath, cap))
                break

    if dangerous_found:
        findings.append(Finding(
            title=f"Skills with sensitive system access ({len(dangerous_found)} skills)",
            description=(
                "Skills provide access to sensitive system capabilities "
                "including camera, iMessage, WhatsApp, and UI automation. "
                "These capabilities could be triggered by prompt injection "
                "attacks via any input channel (Telegram, web UI, metrics "
                "files, PR diffs)."
            ),
            severity=Severity.HIGH,
            agent="static_audit",
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI02"],
            nist_ai_rmf=["GOVERN"],
            evidence=[Evidence(
                type="file_content",
                summary=f"{len(dangerous_found)} dangerous skill capabilities",
                raw_data="\n".join(f"  {f}: {cap}" for f, cap in dangerous_found),
                location="openclaw_codebase",
            )],
            remediation=(
                "Require explicit human confirmation before invoking "
                "sensitive skills (camera, messaging, UI automation). "
                "Implement a separate approval flow for these capabilities."
            ),
            cvss_score=7.0,
            ai_risk_score=8.0,
        ))

    return findings


def check_dashboard_security(files: dict[str, str]) -> list[Finding]:
    """Check nginx dashboard for security issues."""
    findings: list[Finding] = []

    for fpath, content in files.items():
        if "nginx" not in fpath.lower():
            continue

        # Check for CORS wildcard
        if "Access-Control-Allow-Origin" in content and '"*"' in content:
            findings.append(Finding(
                title="Dashboard has wildcard CORS policy",
                description=(
                    "The nginx dashboard serves metrics data with "
                    "Access-Control-Allow-Origin: * header. This allows "
                    "any website to read the metrics data cross-origin, "
                    "including session costs, model usage, and PR diffs."
                ),
                severity=Severity.MEDIUM,
                agent="static_audit",
                owasp_llm=["LLM09"],
                nist_ai_rmf=["MEASURE"],
                evidence=[Evidence(
                    type="config",
                    summary="Wildcard CORS in nginx",
                    raw_data='add_header Access-Control-Allow-Origin "*"',
                    location=fpath,
                )],
                remediation=(
                    "Remove the wildcard CORS header or restrict it to "
                    "specific trusted origins. Add authentication to the "
                    "dashboard (e.g., Basic Auth or token-based auth)."
                ),
                cvss_score=4.5,
            ))

        # Check for directory listing
        if "autoindex on" in content:
            findings.append(Finding(
                title="Dashboard enables directory listing",
                description=(
                    "The nginx dashboard has 'autoindex on' which exposes "
                    "all files in the metrics directory to anyone who can "
                    "access the dashboard."
                ),
                severity=Severity.LOW,
                agent="static_audit",
                owasp_llm=["LLM09"],
                evidence=[Evidence(
                    type="config",
                    summary="Directory listing enabled",
                    raw_data="autoindex on",
                    location=fpath,
                )],
                remediation="Disable directory listing unless required.",
                cvss_score=3.0,
            ))

    return findings


def check_tls_security(root: Path) -> list[Finding]:
    """Check TLS certificate and key files."""
    findings: list[Finding] = []

    # Look for TLS files
    tls_files = list(root.rglob("*.pem")) + list(root.rglob("*.key"))
    cert_files = [f for f in tls_files if "cert" in f.name.lower()]
    key_files = [f for f in tls_files if "key" in f.name.lower()]

    if key_files:
        for key_file in key_files:
            findings.append(Finding(
                title=f"TLS private key stored on disk: {key_file.name}",
                description=(
                    "TLS private key is stored on the filesystem without "
                    "encryption. Anyone with filesystem access can perform "
                    "man-in-the-middle attacks on TLS connections."
                ),
                severity=Severity.MEDIUM,
                agent="static_audit",
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI07"],
                nist_ai_rmf=["MEASURE"],
                evidence=[Evidence(
                    type="file_content",
                    summary="TLS private key on disk",
                    raw_data=str(key_file.relative_to(root)),
                    location="openclaw_codebase",
                )],
                remediation=(
                    "Store TLS private keys in a secrets manager or "
                    "hardware security module. Use automatic certificate "
                    "management (ACME/Let's Encrypt) instead of mkcert."
                ),
                cvss_score=5.0,
            ))

    if cert_files:
        for cert_file in cert_files:
            try:
                content = cert_file.read_text()
                if "mkcert" in content.lower() or "development" in content.lower():
                    findings.append(Finding(
                        title="Self-signed/development TLS certificate in use",
                        description=(
                            "The TLS certificate is generated by mkcert (local "
                            "development CA) and is not publicly trusted."
                        ),
                        severity=Severity.LOW,
                        agent="static_audit",
                        owasp_llm=["LLM09"],
                        nist_ai_rmf=["MEASURE"],
                        evidence=[Evidence(
                            type="config",
                            summary="mkcert development certificate",
                            raw_data=str(cert_file.relative_to(root)),
                            location="openclaw_codebase",
                        )],
                        remediation="Use a publicly trusted CA for production.",
                        cvss_score=3.0,
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(findings: list[Finding], target_name: str) -> ScanReport:
    """Build a ScanReport from collected findings."""

    # Count by severity
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    # Determine overall risk
    if counts[Severity.CRITICAL] > 0:
        overall = Severity.CRITICAL
    elif counts[Severity.HIGH] > 0:
        overall = Severity.HIGH
    elif counts[Severity.MEDIUM] > 0:
        overall = Severity.MEDIUM
    else:
        overall = Severity.LOW

    # Top risks
    top = sorted(
        [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)],
        key=lambda f: (f.cvss_score or 0),
        reverse=True,
    )
    top_risks = [f.title for f in top[:5]]

    executive = ExecutiveSummary(
        overall_risk_level=overall,
        total_findings=len(findings),
        critical_count=counts[Severity.CRITICAL],
        high_count=counts[Severity.HIGH],
        medium_count=counts[Severity.MEDIUM],
        low_count=counts[Severity.LOW],
        info_count=counts[Severity.INFO],
        top_risks=top_risks,
        summary_text=(
            f"Static security audit of OpenClaw identified {len(findings)} "
            f"findings across {sum(1 for c in counts.values() if c > 0)} "
            f"severity levels. {counts[Severity.CRITICAL]} critical and "
            f"{counts[Severity.HIGH]} high-severity issues require immediate "
            f"attention, primarily related to Docker socket exposure, root "
            f"container execution, and hardcoded API credentials."
        ),
    )

    # Risk overview
    risk = RiskOverview(
        ai_risk_score=min(10, sum(f.ai_risk_score or 0 for f in findings if f.ai_risk_score) / max(1, len([f for f in findings if f.ai_risk_score]))),
        attack_surface_score=8.5,
        data_exposure_score=7.0,
        agency_risk_score=9.0,
        supply_chain_score=5.5,
        compliance_score=4.0,
    )

    # OWASP mappings
    owasp_llm: dict[str, list[Finding]] = {}
    owasp_agentic: dict[str, list[Finding]] = {}
    nist: dict[str, list[Finding]] = {}

    for f in findings:
        for cat in f.owasp_llm:
            owasp_llm.setdefault(cat, []).append(f)
        for cat in f.owasp_agentic:
            owasp_agentic.setdefault(cat, []).append(f)
        for cat in f.nist_ai_rmf:
            nist.setdefault(cat, []).append(f)

    # Agent results
    agent_result = AgentResult(
        agent="static_audit",
        findings=findings,
        duration_seconds=0.0,
    )

    return ScanReport(
        scan_id=uuid4(),
        target_name=target_name,
        target_image="openclaw (static analysis)",
        aisec_version=__version__,
        generated_at=datetime.now(timezone.utc),
        language="en",
        executive_summary=executive,
        risk_overview=risk,
        owasp_llm_findings=owasp_llm,
        owasp_agentic_findings=owasp_agentic,
        nist_ai_rmf_findings=nist,
        agent_results={"static_audit": agent_result},
        all_findings=findings,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="AiSec static audit of OpenClaw")
    parser.add_argument("--openclaw-path", type=Path, default=DEFAULT_OPENCLAW_PATH)
    parser.add_argument("--output-dir", type=Path, default=Path("./aisec-reports"))
    args = parser.parse_args()

    root = args.openclaw_path
    output_dir: Path = args.output_dir

    if not root.is_dir():
        print(f"Error: OpenClaw path not found: {root}")
        sys.exit(1)

    print(f"[AiSec] Scanning OpenClaw at: {root}")
    print("[AiSec] Collecting files...")
    files = collect_files(root)
    print(f"[AiSec] Collected {len(files)} text files")

    print("[AiSec] Running security checks...")
    all_findings: list[Finding] = []

    checks = [
        ("Secrets", check_secrets),
        ("PII", check_pii),
        ("Docker", lambda f: check_docker_security(root, f)),
        ("Agent Permissions", check_agent_permissions),
        ("Memory Security", check_memory_security),
        ("Data Retention", check_data_retention),
        ("Skill Security", check_skill_security),
        ("Dashboard", check_dashboard_security),
    ]

    for name, check_fn in checks:
        findings = check_fn(files)
        print(f"  [{name}] {len(findings)} finding(s)")
        all_findings.extend(findings)

    # TLS check needs root path
    tls_findings = check_tls_security(root)
    print(f"  [TLS] {len(tls_findings)} finding(s)")
    all_findings.extend(tls_findings)

    print(f"\n[AiSec] Total findings: {len(all_findings)}")
    for sev in Severity:
        count = sum(1 for f in all_findings if f.severity == sev)
        if count > 0:
            print(f"  {sev.value.upper()}: {count}")

    # Build report
    print("\n[AiSec] Building report...")
    report = build_report(all_findings, "OpenClaw")

    # Render
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_id_short = str(report.scan_id)[:8]
    base = f"aisec-openclaw-{scan_id_short}"

    json_path = json_renderer.render(report, output_dir / f"{base}.json")
    print(f"  JSON: {json_path}")

    html_path = html_renderer.render(report, output_dir / f"{base}.html")
    print(f"  HTML: {html_path}")

    print(f"\n[AiSec] Audit complete. Reports in {output_dir}/")


if __name__ == "__main__":
    main()
