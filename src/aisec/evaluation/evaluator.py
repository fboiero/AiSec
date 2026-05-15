"""Rule-based model-risk evaluator for orchestrator integrations."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import aisec
from aisec.core.enums import Severity
from aisec.evaluation.models import (
    EvaluationEvidence,
    EvaluationFinding,
    FrameworkResult,
    ModelRiskEvaluationRequest,
    ModelRiskEvaluationResult,
    PolicyVerdict,
)

_PII_CLASSES = {
    "pii",
    "personal_data",
    "customer_messages",
    "customer_data",
    "email",
    "dni",
    "health_data",
    "financial_data",
}


def _stable_id(request: ModelRiskEvaluationRequest, *parts: object) -> str:
    content = ":".join(
        [request.schema_version, request.request_id, *(str(part) for part in parts)]
    )
    return str(uuid5(NAMESPACE_URL, content))


def _stable_created_at(request: ModelRiskEvaluationRequest) -> datetime:
    configured = request.context.metadata.get(
        "evaluation_created_at"
    ) or request.context.metadata.get(
        "created_at"
    )
    if isinstance(configured, str) and configured:
        parsed = datetime.fromisoformat(configured.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    return datetime(1970, 1, 1, tzinfo=UTC)


def _has_pii(data_classes: list[str]) -> bool:
    normalized = {item.strip().lower() for item in data_classes}
    return bool(normalized & _PII_CLASSES)


def _evidence(summary: str, *, location: str = "request.target") -> EvaluationEvidence:
    return EvaluationEvidence(type="configuration", summary=summary, location=location)


def _finding(
    *,
    title: str,
    description: str,
    severity: Severity,
    frameworks: list[str],
    remediation: str,
    evidence: list[EvaluationEvidence],
    owasp_llm: list[str] | None = None,
    owasp_agentic: list[str] | None = None,
    nist_ai_rmf: list[str] | None = None,
) -> EvaluationFinding:
    return EvaluationFinding(
        title=title,
        description=description,
        severity=severity,
        frameworks=frameworks,
        owasp_llm=owasp_llm or [],
        owasp_agentic=owasp_agentic or [],
        nist_ai_rmf=nist_ai_rmf or [],
        evidence=evidence,
        remediation=remediation,
    )


def _risk_score(findings: list[EvaluationFinding]) -> float:
    weights = {
        Severity.CRITICAL: 3.0,
        Severity.HIGH: 2.0,
        Severity.MEDIUM: 1.0,
        Severity.LOW: 0.4,
        Severity.INFO: 0.1,
    }
    score = sum(weights[f.severity] for f in findings)
    return min(round(score, 1), 10.0)


def _risk_level(score: float, findings: list[EvaluationFinding]) -> str:
    if any(f.severity == Severity.CRITICAL for f in findings) or score >= 9:
        return "critical"
    if any(f.severity == Severity.HIGH for f in findings) or score >= 6:
        return "high"
    if any(f.severity == Severity.MEDIUM for f in findings) or score >= 3:
        return "medium"
    if findings:
        return "low"
    return "info"


def _framework_results(
    request: ModelRiskEvaluationRequest,
    findings: list[EvaluationFinding],
) -> list[FrameworkResult]:
    results: list[FrameworkResult] = []
    for framework in request.frameworks:
        related = [f for f in findings if framework in f.frameworks]
        severity_counts = Counter(f.severity for f in related)
        score = _risk_score(related)
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in related):
            status = "fail"
        elif related:
            status = "warn"
        else:
            status = "pass"
        summary = "No findings mapped to this framework."
        if related:
            summary = (
                f"{len(related)} finding(s): "
                f"{severity_counts[Severity.CRITICAL]} critical, "
                f"{severity_counts[Severity.HIGH]} high, "
                f"{severity_counts[Severity.MEDIUM]} medium."
            )
        results.append(
            FrameworkResult(
                framework=framework,
                status=status,
                score=score,
                finding_count=len(related),
                summary=summary,
            )
        )
    return results


def _policy_verdict(
    request: ModelRiskEvaluationRequest,
    findings: list[EvaluationFinding],
) -> PolicyVerdict:
    fail_on = str(request.policy.get("fail_on", "critical")).lower()
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "none": 99,
    }
    threshold = severity_order.get(fail_on, 4)
    reasons: list[str] = []
    for finding in findings:
        if severity_order[finding.severity.value] >= threshold:
            reasons.append(f"{finding.severity.value}: {finding.title}")
    if reasons:
        return PolicyVerdict(status="fail", reasons=reasons)
    if findings:
        return PolicyVerdict(
            status="warn",
            reasons=["Findings below policy threshold were detected."],
        )
    return PolicyVerdict(status="pass", reasons=["No findings detected."])


def evaluate_model_risk(request: ModelRiskEvaluationRequest) -> ModelRiskEvaluationResult:
    """Evaluate model, agent, RAG, or workflow risk from a descriptor.

    This evaluator intentionally uses explicit descriptor fields rather than
    reaching into OrchestAI internals. That keeps the integration stable across
    repositories and makes every finding traceable to request evidence.
    """
    target = request.target
    caps = target.capabilities
    safeguards = request.context.safeguards
    has_pii = _has_pii(target.data_classes)
    findings: list[EvaluationFinding] = []
    evidence: list[EvaluationEvidence] = [
        _evidence(
            f"Evaluated {target.type} '{target.name}'"
            + (f" using provider '{target.provider}'." if target.provider else ".")
        )
    ]

    if has_pii and not safeguards.pii_redaction:
        ev = _evidence("Target handles personal data but PII redaction is not enabled.")
        findings.append(
            _finding(
                title="PII processed without redaction control",
                description=(
                    "The target declares personal or customer data classes but "
                    "does not declare an active PII redaction safeguard."
                ),
                severity=Severity.HIGH,
                frameworks=["gdpr", "habeas_data", "nist_ai_rmf"],
                owasp_llm=["LLM02"],
                nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[ev],
                remediation=(
                    "Enable PII redaction or masking before prompts, embeddings, "
                    "logs, and provider calls. Document exceptions with lawful basis."
                ),
            )
        )

    if has_pii and not safeguards.consent_required:
        findings.append(
            _finding(
                title="No consent or lawful-basis control declared for PII use",
                description=(
                    "The evaluation request includes personal data classes but "
                    "does not declare consent or lawful-basis enforcement."
                ),
                severity=Severity.MEDIUM,
                frameworks=["gdpr", "habeas_data", "iso_42001"],
                owasp_llm=["LLM02"],
                nist_ai_rmf=["GOVERN", "MAP"],
                evidence=[_evidence("consent_required=false with PII data classes.")],
                remediation=(
                    "Record the processing basis, enforce consent where required, "
                    "and connect the model use case to the data-processing register."
                ),
            )
        )

    if has_pii and not safeguards.prompt_logging_disabled:
        findings.append(
            _finding(
                title="Prompt logging may retain sensitive data",
                description=(
                    "PII-bearing model interactions can be retained in prompt or "
                    "completion logs unless logging is disabled or scrubbed."
                ),
                severity=Severity.MEDIUM,
                frameworks=["gdpr", "habeas_data", "nist_ai_rmf"],
                owasp_llm=["LLM02"],
                nist_ai_rmf=["MANAGE"],
                evidence=[_evidence("prompt_logging_disabled=false with PII data classes.")],
                remediation=(
                    "Disable raw prompt logging for this use case or store only "
                    "redacted logs with retention controls."
                ),
            )
        )

    if caps.rag_enabled and not safeguards.retrieval_filtering:
        findings.append(
            _finding(
                title="RAG retrieval filtering is not declared",
                description=(
                    "The target uses retrieval augmented generation but does not "
                    "declare document filtering, source allowlisting, or relevance gates."
                ),
                severity=Severity.HIGH,
                frameworks=["owasp_llm", "nist_ai_rmf", "iso_42001"],
                owasp_llm=["LLM01", "LLM08"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[_evidence("rag_enabled=true and retrieval_filtering=false.")],
                remediation=(
                    "Add retrieval filtering, source trust controls, chunk validation, "
                    "and prompt-injection screening for retrieved content."
                ),
            )
        )

    if caps.rag_enabled and has_pii and not safeguards.tenant_isolation:
        findings.append(
            _finding(
                title="RAG with PII lacks declared tenant isolation",
                description=(
                    "A RAG use case with personal data needs explicit tenant, namespace, "
                    "or collection isolation to prevent cross-customer leakage."
                ),
                severity=Severity.HIGH,
                frameworks=["gdpr", "habeas_data", "owasp_llm"],
                owasp_llm=["LLM02", "LLM08"],
                nist_ai_rmf=["MAP", "MANAGE"],
                evidence=[_evidence("rag_enabled=true, PII data classes, tenant_isolation=false.")],
                remediation=(
                    "Enforce vector-store namespace isolation and add regression tests "
                    "for cross-tenant retrieval."
                ),
            )
        )

    if caps.tools_enabled and not safeguards.tool_approval_required:
        findings.append(
            _finding(
                title="Tool use lacks approval control",
                description=(
                    "The target can invoke tools but does not declare an approval, "
                    "allowlist, or policy gate for sensitive actions."
                ),
                severity=Severity.HIGH,
                frameworks=["owasp_agentic", "owasp_llm", "nist_ai_rmf"],
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI02", "ASI03"],
                nist_ai_rmf=["MANAGE"],
                evidence=[_evidence("tools_enabled=true and tool_approval_required=false.")],
                remediation=(
                    "Classify tools by risk, require approval for sensitive tools, "
                    "and enforce least-privilege tool scopes."
                ),
            )
        )

    if caps.code_execution_enabled and not safeguards.human_in_loop:
        findings.append(
            _finding(
                title="Code execution enabled without human-in-the-loop",
                description=(
                    "Model-driven code execution is high risk when it can run "
                    "without a declared human approval boundary."
                ),
                severity=Severity.CRITICAL,
                frameworks=["owasp_agentic", "owasp_llm", "nist_ai_rmf"],
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI05"],
                nist_ai_rmf=["MANAGE"],
                evidence=[_evidence("code_execution_enabled=true and human_in_loop=false.")],
                remediation=(
                    "Disable autonomous code execution or require explicit approval, "
                    "sandboxing, command allowlists, and audit logging."
                ),
            )
        )

    if caps.mcp_enabled and not safeguards.audit_logging:
        findings.append(
            _finding(
                title="MCP/tool activity lacks audit logging",
                description=(
                    "MCP or tool-enabled targets need durable audit logs for tool "
                    "calls, arguments, approvals, and outputs."
                ),
                severity=Severity.MEDIUM,
                frameworks=["owasp_agentic", "iso_42001", "nist_ai_rmf"],
                owasp_agentic=["ASI02", "ASI07"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[_evidence("mcp_enabled=true and audit_logging=false.")],
                remediation=(
                    "Persist tool-call audit events with actor, model, arguments, "
                    "decision, output digest, and tenant/project identifiers."
                ),
            )
        )

    if caps.memory_enabled and has_pii and not safeguards.retention_policy_defined:
        findings.append(
            _finding(
                title="Memory with PII lacks retention policy",
                description=(
                    "Persistent model memory containing personal data needs retention, "
                    "erasure, and minimization controls."
                ),
                severity=Severity.HIGH,
                frameworks=["gdpr", "habeas_data", "owasp_agentic"],
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                evidence=[
                    _evidence(
                        "memory_enabled=true, PII data classes, "
                        "retention_policy_defined=false."
                    )
                ],
                remediation=(
                    "Define retention limits, erasure workflows, and memory minimization "
                    "rules for this model use case."
                ),
            )
        )

    if not safeguards.output_filtering:
        findings.append(
            _finding(
                title="Output filtering is not declared",
                description=(
                    "The target does not declare output filtering for unsafe content, "
                    "sensitive disclosure, or untrusted tool output."
                ),
                severity=Severity.LOW,
                frameworks=["owasp_llm", "nist_ai_rmf"],
                owasp_llm=["LLM05"],
                nist_ai_rmf=["MEASURE", "MANAGE"],
                evidence=[_evidence("output_filtering=false.")],
                remediation=(
                    "Add output validation, sensitive-data filters, and tool-output "
                    "sanitization appropriate to the model use case."
                ),
            )
        )

    if not safeguards.rate_limiting and (caps.tools_enabled or target.provider):
        findings.append(
            _finding(
                title="Rate limiting is not declared",
                description=(
                    "Provider-backed or tool-enabled model integrations should declare "
                    "rate limiting to reduce abuse, extraction, and cost-spike risk."
                ),
                severity=Severity.LOW,
                frameworks=["owasp_llm", "nist_ai_rmf"],
                owasp_llm=["LLM10"],
                nist_ai_rmf=["MANAGE"],
                evidence=[_evidence("rate_limiting=false.")],
                remediation=(
                    "Apply per-user, per-tenant, and per-provider limits with alerting "
                    "for anomalous usage."
                ),
            )
        )

    score = _risk_score(findings)
    overall = _risk_level(score, findings)
    recommendations = sorted({f.remediation for f in findings if f.remediation})
    verdict = _policy_verdict(request, findings)

    for index, item in enumerate(evidence):
        item.id = _stable_id(request, "result-evidence", index, item.type, item.summary, item.location)
    for index, finding in enumerate(findings):
        finding.id = _stable_id(request, "finding", index, finding.title)
        for evidence_index, item in enumerate(finding.evidence):
            item.id = _stable_id(
                request,
                "finding-evidence",
                index,
                evidence_index,
                item.type,
                item.summary,
                item.location,
            )

    return ModelRiskEvaluationResult(
        evaluation_id=_stable_id(request, "result"),
        request_id=request.request_id,
        engine_version=aisec.__version__,
        created_at=_stable_created_at(request),
        target=target,
        overall_risk=overall,  # type: ignore[arg-type]
        risk_score=score,
        frameworks=_framework_results(request, findings),
        findings=findings,
        evidence=evidence,
        recommendations=recommendations,
        policy_verdict=verdict,
        metadata={
            "source": request.source,
            "organization_id": request.context.organization_id,
            "project_id": request.context.project_id,
        },
    )
