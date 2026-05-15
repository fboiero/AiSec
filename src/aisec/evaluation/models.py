"""Pydantic models for the AiSec model-risk evaluation protocol."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from aisec.core.enums import Severity

SCHEMA_VERSION = "aisec.model_risk.v1"

TargetType = Literal["model", "agent", "rag_pipeline", "workflow"]
RiskLevel = Literal["critical", "high", "medium", "low", "info"]
VerdictStatus = Literal["pass", "warn", "fail"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EvaluationCapabilities(BaseModel):
    """Capabilities enabled for the evaluated model or agent integration."""

    rag_enabled: bool = False
    tools_enabled: bool = False
    memory_enabled: bool = False
    mcp_enabled: bool = False
    code_execution_enabled: bool = False
    web_access_enabled: bool = False
    fine_tuning_enabled: bool = False
    multimodal_enabled: bool = False


class EvaluationSafeguards(BaseModel):
    """Controls already present in the consuming platform."""

    pii_redaction: bool = False
    prompt_logging_disabled: bool = False
    consent_required: bool = False
    retention_policy_defined: bool = False
    human_in_loop: bool = False
    tool_approval_required: bool = False
    output_filtering: bool = False
    retrieval_filtering: bool = False
    tenant_isolation: bool = False
    audit_logging: bool = False
    rate_limiting: bool = False


class EvaluationTarget(BaseModel):
    """Model, agent, RAG pipeline, or workflow being evaluated."""

    type: TargetType = "model"
    name: str
    provider: str = ""
    model_id: str = ""
    environment: str = "unknown"
    usage_context: str = ""
    capabilities: EvaluationCapabilities = Field(default_factory=EvaluationCapabilities)
    data_classes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationContext(BaseModel):
    """Execution context provided by OrchestAI or another orchestrator."""

    organization_id: str = ""
    project_id: str = ""
    requested_by: str = ""
    jurisdiction: str = ""
    safeguards: EvaluationSafeguards = Field(default_factory=EvaluationSafeguards)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelRiskEvaluationRequest(BaseModel):
    """Input contract for optional model-risk evaluation."""

    schema_version: str = SCHEMA_VERSION
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = "orchestai"
    target: EvaluationTarget
    frameworks: list[str] = Field(
        default_factory=lambda: [
            "owasp_llm",
            "owasp_agentic",
            "nist_ai_rmf",
            "gdpr",
            "habeas_data",
        ]
    )
    context: EvaluationContext = Field(default_factory=EvaluationContext)
    policy: dict[str, Any] = Field(default_factory=dict)


class EvaluationEvidence(BaseModel):
    """Evidence item generated or forwarded during evaluation."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str
    summary: str
    location: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationFinding(BaseModel):
    """Normalized finding returned to the orchestrator."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    severity: Severity
    frameworks: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    owasp_agentic: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)
    evidence: list[EvaluationEvidence] = Field(default_factory=list)
    remediation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class FrameworkResult(BaseModel):
    """Framework-level rollup for the evaluated target."""

    framework: str
    status: VerdictStatus
    score: float = 0.0
    finding_count: int = 0
    summary: str = ""


class PolicyVerdict(BaseModel):
    """Optional gate-style result for CI/CD or approval workflows."""

    status: VerdictStatus
    reasons: list[str] = Field(default_factory=list)


class ModelRiskEvaluationResult(BaseModel):
    """Output contract consumed by OrchestAI compliance flows."""

    schema_version: str = SCHEMA_VERSION
    evaluation_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    engine: str = "aisec"
    engine_version: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    target: EvaluationTarget
    overall_risk: RiskLevel
    risk_score: float
    frameworks: list[FrameworkResult] = Field(default_factory=list)
    findings: list[EvaluationFinding] = Field(default_factory=list)
    evidence: list[EvaluationEvidence] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    policy_verdict: PolicyVerdict
    metadata: dict[str, Any] = Field(default_factory=dict)
