from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aisec.cli.app import app
from aisec.core.enums import Severity
from aisec.evaluation import (
    ModelRiskEvaluationRequest,
    ModelRiskEvaluationResult,
    evaluate_model_risk,
)


def _request(**overrides: object) -> ModelRiskEvaluationRequest:
    payload = {
        "request_id": "test-request",
        "source": "orchestai",
        "target": {
            "type": "rag_pipeline",
            "name": "Customer RAG",
            "provider": "openai",
            "model_id": "gpt-4.1",
            "capabilities": {
                "rag_enabled": True,
                "tools_enabled": True,
                "code_execution_enabled": False,
            },
            "data_classes": ["pii", "customer_messages"],
        },
        "frameworks": ["owasp_llm", "owasp_agentic", "nist_ai_rmf", "gdpr", "habeas_data"],
        "context": {
            "organization_id": "xcapit",
            "project_id": "orchestai",
            "safeguards": {
                "pii_redaction": False,
                "prompt_logging_disabled": False,
                "consent_required": False,
                "retrieval_filtering": False,
                "tenant_isolation": False,
                "tool_approval_required": False,
                "output_filtering": False,
                "rate_limiting": False,
            },
        },
        "policy": {"fail_on": "critical"},
    }
    payload.update(overrides)
    return ModelRiskEvaluationRequest.model_validate(payload)


def test_evaluate_model_risk_returns_normalized_findings() -> None:
    result = evaluate_model_risk(_request())

    assert result.schema_version == "aisec.model_risk.v1"
    assert result.request_id == "test-request"
    assert result.engine == "aisec"
    assert result.overall_risk in {"high", "critical"}
    assert result.risk_score > 0
    assert result.findings
    assert any(f.severity == Severity.HIGH for f in result.findings)
    assert any("gdpr" in f.frameworks for f in result.findings)
    assert any("owasp_llm" in f.frameworks for f in result.findings)


def test_framework_rollup_summaries_use_framework_scoped_counts() -> None:
    result = evaluate_model_risk(
        _request(
            frameworks=["gdpr"],
            target={
                "type": "agent",
                "name": "Code Agent",
                "capabilities": {
                    "code_execution_enabled": True,
                },
                "data_classes": [],
            },
            context={
                "safeguards": {
                    "human_in_loop": False,
                    "output_filtering": False,
                    "rate_limiting": False,
                },
            },
        )
    )

    gdpr = result.frameworks[0]
    assert gdpr.framework == "gdpr"
    assert gdpr.finding_count == 0
    assert gdpr.summary == "No findings mapped to this framework."


def test_evaluate_model_risk_is_deterministic_for_same_request() -> None:
    request = _request()

    first = evaluate_model_risk(request).model_dump(mode="json")
    second = evaluate_model_risk(request).model_dump(mode="json")

    assert first == second


def test_all_findings_include_required_integration_fields() -> None:
    result = evaluate_model_risk(_request())

    assert result.findings
    for finding in result.findings:
        assert finding.id
        assert finding.severity
        assert finding.frameworks
        assert finding.evidence
        assert finding.remediation
        for evidence in finding.evidence:
            assert evidence.id
            assert evidence.type
            assert evidence.summary


def test_policy_verdict_fails_on_high_when_requested() -> None:
    result = evaluate_model_risk(_request(policy={"fail_on": "high"}))

    assert result.policy_verdict.status == "fail"
    assert result.policy_verdict.reasons


def test_policy_verdict_warns_when_fail_on_is_critical() -> None:
    req = _request()
    req.target.capabilities.code_execution_enabled = False

    result = evaluate_model_risk(req)

    assert result.policy_verdict.status in {"warn", "fail"}


def test_evaluate_model_cli_writes_result(tmp_path) -> None:
    runner = CliRunner()
    input_path = tmp_path / "request.json"
    output_path = tmp_path / "result.json"
    input_path.write_text(_request().model_dump_json(indent=2), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "evaluate",
            "model",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--fail-on",
            "none",
            "--quiet",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == "aisec.model_risk.v1"
    assert data["request_id"] == "test-request"
    assert data["target"]["name"] == "Customer RAG"


def test_evaluate_schema_cli_writes_json_schemas(tmp_path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "evaluate",
            "schema",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    request_schema = tmp_path / "model-risk-request.schema.json"
    result_schema = tmp_path / "model-risk-result.schema.json"
    assert request_schema.exists()
    assert result_schema.exists()
    request_data = json.loads(request_schema.read_text(encoding="utf-8"))
    result_data = json.loads(result_schema.read_text(encoding="utf-8"))
    assert request_data["title"] == "ModelRiskEvaluationRequest"
    assert result_data["title"] == "ModelRiskEvaluationResult"


def test_documented_examples_parse_and_evaluate() -> None:
    examples_dir = Path("docs/examples")
    for path in examples_dir.glob("*risk-request.json"):
        request = ModelRiskEvaluationRequest.model_validate_json(path.read_text(encoding="utf-8"))
        result = evaluate_model_risk(request)
        assert result.schema_version == "aisec.model_risk.v1"
        assert result.request_id == request.request_id
        assert result.target.name == request.target.name


def test_documented_result_example_matches_schema() -> None:
    path = Path("docs/examples/orchestai-model-risk-result.json")
    result = ModelRiskEvaluationResult.model_validate_json(path.read_text(encoding="utf-8"))

    assert result.schema_version == "aisec.model_risk.v1"
    assert result.request_id == "orchestai-epec-demo-001"
    assert result.findings
