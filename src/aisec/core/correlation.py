"""Cross-agent correlation engine for compound risk identification.

Analyses findings from multiple agents to identify compound risks that
emerge when vulnerabilities from different domains are present together.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedRisk:
    """A compound risk identified by cross-referencing findings from multiple agents."""

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str = ""
    severity: Severity = Severity.HIGH
    contributing_findings: list[UUID] = field(default_factory=list)
    agents_involved: list[str] = field(default_factory=list)
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


# Correlation rules: each rule defines conditions across agents that,
# when met together, indicate a compound risk.
CORRELATION_RULES: list[dict[str, Any]] = [
    {
        "name": "Exposed Secret + Open Port = Critical Data Leak",
        "conditions": [
            {"agent": "dataflow", "title_contains": "credential", "any_title": True},
            {"agent": "network", "title_contains": "port", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Hardcoded credentials combined with open network ports create "
            "immediate data exfiltration risk. An attacker who discovers the "
            "exposed port can use the hardcoded credentials to access protected "
            "resources."
        ),
        "remediation": (
            "Remove hardcoded credentials and use a secrets manager. "
            "Restrict network exposure to only necessary ports."
        ),
    },
    {
        "name": "No Input Validation + No Guardrails = Prompt Injection",
        "conditions": [
            {"agent": "prompt_security", "title_contains": "validation", "any_title": True},
            {"agent": "guardrails", "title_contains": "guardrail", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Absence of both input validation AND guardrails makes prompt "
            "injection trivially exploitable. The AI agent has no defense "
            "layers against adversarial inputs."
        ),
        "remediation": (
            "Implement both input validation and output guardrails. Use a "
            "defense-in-depth approach with multiple validation layers."
        ),
    },
    {
        "name": "Privileged Container + Code Execution = Container Escape",
        "conditions": [
            {"agent": "permission", "severity_gte": Severity.MEDIUM},
            {"agent": "adversarial", "title_contains": "execution", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Elevated container privileges combined with code execution "
            "patterns enable container escape. An attacker can leverage "
            "code execution to break out of the container using the "
            "elevated privileges."
        ),
        "remediation": (
            "Drop all unnecessary capabilities with --cap-drop ALL. "
            "Eliminate code execution patterns or sandbox them securely."
        ),
    },
    {
        "name": "No Rate Limit + No Auth = Unbounded Consumption",
        "conditions": [
            {"agent": "guardrails", "title_contains": "rate limit", "any_title": True},
            {"agent": "guardrails", "title_contains": "auth", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Without rate limiting or authentication, the system is vulnerable "
            "to resource exhaustion and cost attacks. Any user can make "
            "unlimited requests to the AI service."
        ),
        "remediation": (
            "Implement authentication and rate limiting on all endpoints. "
            "Set per-user and global rate limits."
        ),
    },
    {
        "name": "Supply Chain Weak + No SBOM = Unverifiable Dependencies",
        "conditions": [
            {"agent": "supply_chain", "severity_gte": Severity.MEDIUM},
            {"agent": "sbom", "finding_count_eq": 0},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Supply chain issues without SBOM make it impossible to verify "
            "dependency integrity. Organizations cannot audit what software "
            "components are included or verify their provenance."
        ),
        "remediation": (
            "Generate and maintain an SBOM (CycloneDX or SPDX). Pin all "
            "dependencies and verify checksums."
        ),
    },
    {
        "name": "Static Vulnerabilities + No Monitoring = Blind Exploitation",
        "conditions": [
            {"agent": "static_analysis", "severity_gte": Severity.HIGH},
            {"agent": "runtime_behavior", "finding_count_eq": 0},
        ],
        "severity": Severity.HIGH,
        "description": (
            "High-severity code vulnerabilities exist but no runtime monitoring "
            "is in place to detect exploitation. Attacks exploiting these "
            "vulnerabilities will go undetected."
        ),
        "remediation": (
            "Fix the identified code vulnerabilities. Implement runtime "
            "monitoring and alerting for anomalous behavior."
        ),
    },
    {
        "name": "Vulnerable Dependencies + Exposed API = Remote Exploitation",
        "conditions": [
            {"agent": "dependency_audit", "severity_gte": Severity.HIGH},
            {"agent": "api_security", "title_contains": "unauth", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Known vulnerable dependencies combined with unauthenticated API "
            "endpoints create a remote exploitation path. Attackers can reach "
            "the vulnerable code through the exposed API."
        ),
        "remediation": (
            "Upgrade vulnerable dependencies immediately. Add authentication "
            "to all API endpoints."
        ),
    },
    {
        "name": "IaC Misconfig + Privileged Mode = Infrastructure Compromise",
        "conditions": [
            {"agent": "iac_security", "severity_gte": Severity.HIGH},
            {"agent": "permission", "title_contains": "privileged", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Infrastructure-as-code misconfigurations combined with privileged "
            "container execution create a path to full infrastructure compromise."
        ),
        "remediation": (
            "Fix IaC misconfigurations. Remove privileged mode and apply "
            "least-privilege principle to container configuration."
        ),
    },
    # --- v1.4.0 correlation rules ---
    {
        "name": "Taint Flow + No Sanitization = Code Injection",
        "conditions": [
            {"agent": "taint_analysis", "severity_gte": Severity.HIGH},
            {"agent": "static_analysis", "title_contains": "eval", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Untrusted data flows reach dangerous sinks (eval/exec) confirmed by "
            "both taint analysis and static analysis. This is a confirmed code "
            "injection path."
        ),
        "remediation": (
            "Remove eval/exec usage or ensure all tainted data is sanitized "
            "before reaching these sinks. Use ast.literal_eval() for safe parsing."
        ),
    },
    {
        "name": "Unsafe Deserialization + External Input = RCE",
        "conditions": [
            {"agent": "serialization", "severity_gte": Severity.CRITICAL},
            {"agent": "network", "title_contains": "port", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Critical deserialization vulnerabilities combined with open network "
            "ports create a remote code execution path. Attackers can send "
            "malicious serialized payloads through exposed ports."
        ),
        "remediation": (
            "Replace unsafe deserialization with safe alternatives (safetensors, "
            "json). Restrict network exposure to necessary ports only."
        ),
    },
    {
        "name": "Git Secrets + Current HEAD = Active Credential Exposure",
        "conditions": [
            {"agent": "git_history_secrets", "severity_gte": Severity.CRITICAL},
            {"agent": "dataflow", "title_contains": "credential", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Secrets found in git history are also detected as active credentials "
            "in the current codebase. These credentials are actively exposed and "
            "accessible to anyone with repository access."
        ),
        "remediation": (
            "Rotate ALL exposed credentials immediately. Remove from git history "
            "with git filter-repo. Migrate to a secrets manager."
        ),
    },
    {
        "name": "Transitive Vuln + No SBOM = Hidden Supply Chain Risk",
        "conditions": [
            {"agent": "deep_dependency", "severity_gte": Severity.HIGH},
            {"agent": "sbom", "finding_count_eq": 0},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Transitive dependency vulnerabilities exist but no SBOM is generated, "
            "making it impossible to track and audit the full dependency chain."
        ),
        "remediation": (
            "Generate an SBOM (CycloneDX/SPDX) for full dependency visibility. "
            "Pin transitive dependencies and monitor for vulnerabilities."
        ),
    },
    {
        "name": "ReDoS + Public API = Denial of Service",
        "conditions": [
            {"agent": "resource_exhaustion", "title_contains": "ReDoS", "any_title": True},
            {"agent": "api_security", "title_contains": "unauth", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "ReDoS-vulnerable regex patterns combined with unauthenticated API "
            "endpoints allow remote denial-of-service attacks. Attackers can "
            "craft inputs that cause catastrophic regex backtracking."
        ),
        "remediation": (
            "Fix ReDoS patterns using non-backtracking alternatives. Add "
            "authentication and rate limiting to all API endpoints."
        ),
    },
    {
        "name": "No mTLS + Sensitive Data Flow = Data Interception",
        "conditions": [
            {"agent": "inter_service", "title_contains": "TLS", "any_title": True},
            {"agent": "dataflow", "title_contains": "PII", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Internal services communicate without TLS while handling PII data. "
            "This allows network-level interception of sensitive data."
        ),
        "remediation": (
            "Implement mTLS for all inter-service communication that handles "
            "PII or sensitive data. Use service mesh for automatic mTLS."
        ),
    },
    {
        "name": "PII to LLM + No Consent = Privacy Violation",
        "conditions": [
            {"agent": "data_lineage", "title_contains": "PII", "any_title": True},
            {"agent": "privacy", "title_contains": "consent", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "PII data is sent to LLM APIs without proper consent mechanisms. "
            "This violates GDPR Art. 6 (lawful basis) and CCPA requirements "
            "for notice at collection."
        ),
        "remediation": (
            "Implement consent collection before PII processing. Anonymize PII "
            "before sending to LLM APIs. Document lawful basis for processing."
        ),
    },
    {
        "name": "Embedding Exposed + No Auth = Training Data Leak",
        "conditions": [
            {"agent": "embedding_leakage", "severity_gte": Severity.HIGH},
            {"agent": "api_security", "title_contains": "unauth", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Embedding/vector endpoints are exposed without authentication. "
            "Combined with unauthenticated API endpoints, this enables model "
            "inversion attacks to extract training data."
        ),
        "remediation": (
            "Add authentication to all embedding and search endpoints. "
            "Implement rate limiting and anomaly detection for query patterns."
        ),
    },
    {
        "name": "Unsafe Pickle + Unpinned Deps = Model Poisoning",
        "conditions": [
            {"agent": "serialization", "title_contains": "pickle", "any_title": True},
            {"agent": "dependency_audit", "title_contains": "unpinned", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Pickle-based model loading combined with unpinned dependencies "
            "creates a model poisoning attack vector. Attackers can inject "
            "malicious payloads through compromised package versions."
        ),
        "remediation": (
            "Switch to safetensors for model serialization. Pin all dependencies "
            "to exact versions with hash verification."
        ),
    },
    {
        "name": "Webhook No HMAC + Open Port = Request Forgery",
        "conditions": [
            {"agent": "inter_service", "title_contains": "webhook", "any_title": True},
            {"agent": "network", "title_contains": "port", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "Webhook handlers lack HMAC verification and are reachable via open "
            "network ports. Attackers can forge webhook requests to trigger "
            "unauthorized actions."
        ),
        "remediation": (
            "Implement HMAC signature verification on all webhook endpoints. "
            "Restrict network access to known webhook sources."
        ),
    },
    # --- v1.5.0 correlation rules ---
    {
        "name": "RAG Injection + No Input Validation = Data Exfiltration via Retrieval",
        "conditions": [
            {"agent": "rag_security", "title_contains": "injection", "any_title": True},
            {"agent": "prompt_security", "title_contains": "validation", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "RAG document injection vectors combined with missing input validation "
            "enable attackers to inject malicious documents that exfiltrate data "
            "through the retrieval pipeline."
        ),
        "remediation": (
            "Validate all document loader inputs. Implement input validation and "
            "content filtering on both ingestion and retrieval paths."
        ),
    },
    {
        "name": "MCP No Auth + Unrestricted Tools = Agent Takeover",
        "conditions": [
            {"agent": "mcp_security", "title_contains": "unauthenticated", "any_title": True},
            {"agent": "tool_chain", "severity_gte": Severity.HIGH},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Unauthenticated MCP server combined with unrestricted tool access "
            "allows any client to invoke dangerous tools, leading to full "
            "agent takeover."
        ),
        "remediation": (
            "Add authentication to the MCP server. Implement tool allowlists "
            "and approval flows for sensitive operations."
        ),
    },
    {
        "name": "Tool Chain No Sandbox + Code Execution = Arbitrary RCE",
        "conditions": [
            {"agent": "tool_chain", "title_contains": "sandbox", "any_title": True},
            {"agent": "permission", "title_contains": "privileged", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Code execution tools without sandboxing running in a privileged "
            "container enable arbitrary remote code execution with host-level "
            "access."
        ),
        "remediation": (
            "Sandbox all code execution tools in isolated containers. Remove "
            "privileged mode and drop unnecessary capabilities."
        ),
    },
    {
        "name": "Memory Poisoning + No Encryption = Persistent Compromise",
        "conditions": [
            {"agent": "agent_memory", "title_contains": "poisoning", "any_title": True},
            {"agent": "agent_memory", "title_contains": "unencrypted", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Memory poisoning vectors combined with unencrypted storage allow "
            "attackers to persistently manipulate agent behavior by modifying "
            "stored conversation context."
        ),
        "remediation": (
            "Encrypt all memory stores. Validate and sanitize content before "
            "writing to memory. Implement integrity checks on stored data."
        ),
    },
    {
        "name": "Poisoned Training Data + No Validation = Model Backdoor",
        "conditions": [
            {"agent": "fine_tuning", "title_contains": "untrusted", "any_title": True},
            {"agent": "model_scan", "severity_gte": Severity.MEDIUM},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Training on untrusted data without validation combined with model "
            "security issues creates a model backdoor risk. Poisoned training "
            "data can embed hidden behaviors in the fine-tuned model."
        ),
        "remediation": (
            "Validate all training data sources. Implement data quality gates "
            "and anomaly detection. Scan fine-tuned models for backdoors."
        ),
    },
    {
        "name": "CI Secrets Exposed + No Model Signing = Supply Chain Attack",
        "conditions": [
            {"agent": "cicd_pipeline", "title_contains": "secret", "any_title": True},
            {"agent": "cicd_pipeline", "title_contains": "signing", "any_title": True},
        ],
        "severity": Severity.CRITICAL,
        "description": (
            "Secrets exposed in CI/CD configurations combined with missing model "
            "signing create a supply chain attack vector. Attackers can use "
            "stolen credentials to push poisoned models."
        ),
        "remediation": (
            "Move all secrets to CI/CD platform secret stores. Implement model "
            "signing with cosign or sigstore. Verify signatures before deployment."
        ),
    },
    {
        "name": "RAG + Embedding No Auth = Retrieval Manipulation",
        "conditions": [
            {"agent": "rag_security", "title_contains": "retrieval", "any_title": True},
            {"agent": "embedding_leakage", "title_contains": "without authentication", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "RAG pipeline retrieval issues combined with unauthenticated vector "
            "databases allow attackers to manipulate search results by injecting "
            "or modifying embeddings directly."
        ),
        "remediation": (
            "Authenticate all vector database connections. Add metadata filtering "
            "to retrieval queries. Monitor for anomalous embedding updates."
        ),
    },
    {
        "name": "Fine-tuning PII + No Consent = Regulatory Violation",
        "conditions": [
            {"agent": "fine_tuning", "title_contains": "PII", "any_title": True},
            {"agent": "data_lineage", "title_contains": "consent", "any_title": True},
        ],
        "severity": Severity.HIGH,
        "description": (
            "PII in training data without consent mechanisms violates GDPR Art. 6 "
            "(lawful basis for processing) and CCPA requirements. Fine-tuning on "
            "personal data requires explicit consent or legitimate interest basis."
        ),
        "remediation": (
            "Implement consent collection before using PII for training. Scrub PII "
            "from training data. Document lawful basis for processing under GDPR."
        ),
    },
]


def _check_condition(
    condition: dict[str, Any],
    agent_findings: dict[str, list[Finding]],
) -> list[Finding]:
    """Check a single condition against agent findings, return matching findings."""
    agent_name = condition["agent"]
    findings = agent_findings.get(agent_name, [])

    # Check finding_count_eq (e.g., no findings from an agent)
    if "finding_count_eq" in condition:
        if len(findings) == condition["finding_count_eq"]:
            return []  # Condition met but no findings to reference
        return []  # Condition not met

    if not findings:
        return []

    matched: list[Finding] = []

    for finding in findings:
        # Check severity threshold
        if "severity_gte" in condition:
            severity_order = list(Severity)
            if severity_order.index(finding.severity) > severity_order.index(
                condition["severity_gte"]
            ):
                continue

        # Check title contains
        if "title_contains" in condition:
            search_term = condition["title_contains"].lower()
            if condition.get("any_title"):
                # Match if ANY finding from this agent contains the term
                if search_term not in finding.title.lower():
                    continue

        matched.append(finding)

    return matched


def correlate(agent_results: dict[str, AgentResult]) -> list[CorrelatedRisk]:
    """Run correlation rules against all agent results.

    Args:
        agent_results: Dict mapping agent name to its AgentResult.

    Returns:
        List of correlated compound risks identified.
    """
    # Build a lookup: agent_name -> list of findings
    agent_findings: dict[str, list[Finding]] = {}
    for name, result in agent_results.items():
        agent_findings[name] = result.findings

    correlated_risks: list[CorrelatedRisk] = []

    for rule in CORRELATION_RULES:
        conditions = rule["conditions"]
        all_matched_findings: list[Finding] = []
        all_agents: list[str] = []
        conditions_met = True

        for condition in conditions:
            agent_name = condition["agent"]

            # Special case: finding_count_eq == 0 means "agent has no findings"
            if "finding_count_eq" in condition:
                count = len(agent_findings.get(agent_name, []))
                if count != condition["finding_count_eq"]:
                    conditions_met = False
                    break
                all_agents.append(agent_name)
                continue

            matched = _check_condition(condition, agent_findings)
            if not matched:
                conditions_met = False
                break
            all_matched_findings.extend(matched)
            all_agents.append(agent_name)

        if conditions_met:
            risk = CorrelatedRisk(
                name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                contributing_findings=[f.id for f in all_matched_findings],
                agents_involved=list(dict.fromkeys(all_agents)),
                remediation=rule["remediation"],
            )
            correlated_risks.append(risk)
            logger.info(
                "Correlated risk identified: %s (agents: %s)",
                risk.name,
                ", ".join(risk.agents_involved),
            )

    return correlated_risks
