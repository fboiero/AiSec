from __future__ import annotations

import json
from pathlib import Path

from aisec.evaluation import ModelRiskEvaluationRequest, evaluate_model_risk


EXAMPLES = Path("docs/examples")


def _evaluate_example(filename: str):
    payload = json.loads((EXAMPLES / filename).read_text(encoding="utf-8"))
    request = ModelRiskEvaluationRequest.model_validate(payload)
    return evaluate_model_risk(request)


def test_orchestai_customer_support_rag_use_case_is_validated() -> None:
    result = _evaluate_example("orchestai-usecase-customer-support-rag.json")
    titles = {finding.title for finding in result.findings}
    frameworks = {framework.framework: framework for framework in result.frameworks}

    assert result.schema_version == "aisec.model_risk.v1"
    assert result.target.name == "OrchestAI Customer Support RAG"
    assert result.overall_risk == "high"
    assert result.policy_verdict.status == "warn"
    assert "PII processed without redaction control" in titles
    assert "RAG retrieval filtering is not declared" in titles
    assert "RAG with PII lacks declared tenant isolation" in titles
    assert frameworks["gdpr"].finding_count >= 2
    assert frameworks["owasp_llm"].status == "fail"


def test_orchestai_ops_agent_mcp_use_case_is_validated() -> None:
    result = _evaluate_example("orchestai-usecase-ops-agent-mcp.json")
    titles = {finding.title for finding in result.findings}
    frameworks = {framework.framework: framework for framework in result.frameworks}

    assert result.schema_version == "aisec.model_risk.v1"
    assert result.target.name == "OrchestAI Ops Agent With MCP"
    assert result.overall_risk == "critical"
    assert result.policy_verdict.status == "fail"
    assert "Code execution enabled without human-in-the-loop" in titles
    assert "Tool use lacks approval control" in titles
    assert "MCP/tool activity lacks audit logging" in titles
    assert "Memory with PII lacks retention policy" in titles
    assert frameworks["owasp_agentic"].status == "fail"
    assert frameworks["nist_ai_rmf"].finding_count >= 5
