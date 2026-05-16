from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aisec.cli.app import app
from aisec.evaluation import (
    ModelRiskEvaluationRequest,
    compare_model_risk_baseline,
    discover_model_risk_artifacts,
    evaluate_model_risk,
    export_model_risk_framework_evidence,
    fingerprint_model_risk_finding,
    load_model_risk_artifacts,
    load_single_model_risk_artifact,
    render_model_risk_comparison_markdown,
    render_model_risk_framework_evidence_markdown,
    render_model_risk_summary_markdown,
    summarize_model_risk_artifacts,
)


def _request(name: str, *, request_id: str, fail_on: str = "none") -> ModelRiskEvaluationRequest:
    return ModelRiskEvaluationRequest.model_validate(
        {
            "request_id": request_id,
            "source": "orchestai",
            "target": {
                "type": "rag_pipeline",
                "name": name,
                "provider": "openai",
                "model_id": "gpt-4.1",
                "capabilities": {
                    "rag_enabled": True,
                    "tools_enabled": True,
                },
                "data_classes": ["pii"],
            },
            "frameworks": ["owasp_llm", "owasp_agentic", "gdpr"],
            "context": {
                "safeguards": {
                    "pii_redaction": False,
                    "prompt_logging_disabled": False,
                    "retrieval_filtering": False,
                    "tool_approval_required": False,
                }
            },
            "policy": {"fail_on": fail_on},
        }
    )


def _clean_request(name: str, *, request_id: str) -> ModelRiskEvaluationRequest:
    return ModelRiskEvaluationRequest.model_validate(
        {
            "request_id": request_id,
            "source": "orchestai",
            "target": {
                "type": "rag_pipeline",
                "name": name,
                "provider": "openai",
                "model_id": "gpt-4.1",
                "capabilities": {
                    "rag_enabled": True,
                    "tools_enabled": False,
                },
                "data_classes": ["pii"],
            },
            "frameworks": ["owasp_llm", "owasp_agentic", "gdpr"],
            "context": {
                "safeguards": {
                    "pii_redaction": True,
                    "prompt_logging_disabled": True,
                    "consent_required": True,
                    "retention_policy_defined": True,
                    "retrieval_filtering": True,
                    "tenant_isolation": True,
                    "output_filtering": True,
                    "audit_logging": True,
                    "rate_limiting": True,
                }
            },
            "policy": {"fail_on": "critical"},
        }
    )


def _write_result(path: Path, request: ModelRiskEvaluationRequest) -> None:
    result = evaluate_model_risk(request)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def test_discover_and_load_model_risk_artifacts_from_directory(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "aisec-results"
    artifact_dir.mkdir()
    first = artifact_dir / "first.json"
    second = artifact_dir / "nested" / "second.json"
    second.parent.mkdir()
    _write_result(first, _request("Customer RAG", request_id="first"))
    _write_result(second, _request("Tool Agent", request_id="second"))

    paths = discover_model_risk_artifacts([artifact_dir])
    artifacts = load_model_risk_artifacts(paths)

    assert paths == sorted([first.resolve(), second.resolve()])
    assert len(artifacts) == 2
    assert {result.request_id for _, result in artifacts} == {"first", "second"}


def test_summarize_model_risk_artifacts_rolls_up_counts(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    _write_result(artifact, _request("Customer RAG", request_id="summary"))

    summary = summarize_model_risk_artifacts(load_model_risk_artifacts([artifact]))

    assert summary.artifact_count == 1
    assert summary.total_findings > 0
    assert summary.severity_counts["high"] >= 1
    assert summary.targets[0].target_name == "Customer RAG"
    assert summary.top_findings


def test_render_model_risk_summary_markdown_contains_ci_tables(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    _write_result(artifact, _request("Customer RAG", request_id="markdown"))

    summary = summarize_model_risk_artifacts(load_model_risk_artifacts([artifact]))
    markdown = render_model_risk_summary_markdown(summary)

    assert "# AiSec Model-Risk Summary" in markdown
    assert "## Severity Counts" in markdown
    assert "## Targets" in markdown
    assert "Customer RAG" in markdown


def test_evaluate_summarize_cli_writes_markdown(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    output = tmp_path / "summary.md"
    _write_result(artifact, _request("Customer RAG", request_id="cli"))

    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "summarize",
            "--input",
            str(artifact),
            "--output",
            str(output),
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "Customer RAG" in output.read_text(encoding="utf-8")


def test_evaluate_summarize_cli_writes_json(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    output = tmp_path / "summary.json"
    _write_result(artifact, _request("Customer RAG", request_id="json"))

    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "summarize",
            "--input",
            str(artifact),
            "--output",
            str(output),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["artifact_count"] == 1
    assert data["targets"][0]["target_name"] == "Customer RAG"


def test_export_model_risk_framework_evidence_groups_findings(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    _write_result(artifact, _request("Customer RAG", request_id="framework-evidence"))

    export = export_model_risk_framework_evidence(
        load_model_risk_artifacts([artifact]),
        frameworks={"gdpr"},
    )
    markdown = render_model_risk_framework_evidence_markdown(export)

    assert export.artifact_count == 1
    assert [report.framework for report in export.frameworks] == ["gdpr"]
    assert export.frameworks[0].finding_count > 0
    assert export.frameworks[0].target_names == ["Customer RAG"]
    assert "# AiSec Framework Evidence Export" in markdown
    assert "## gdpr" in markdown
    assert "Customer RAG" in markdown


def test_evaluate_evidence_cli_writes_json(tmp_path: Path) -> None:
    artifact = tmp_path / "result.json"
    output = tmp_path / "framework-evidence.json"
    _write_result(artifact, _request("Customer RAG", request_id="evidence-cli"))

    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "evidence",
            "--input",
            str(artifact),
            "--output",
            str(output),
            "--format",
            "json",
            "--framework",
            "gdpr",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["artifact_count"] == 1
    assert data["frameworks"][0]["framework"] == "gdpr"
    assert data["frameworks"][0]["findings"]


def test_load_model_risk_artifacts_can_skip_invalid_json(tmp_path: Path) -> None:
    valid = tmp_path / "valid.json"
    invalid = tmp_path / "invalid.json"
    _write_result(valid, _request("Customer RAG", request_id="valid"))
    invalid.write_text('{"not": "a model-risk result"}', encoding="utf-8")

    artifacts = load_model_risk_artifacts([valid, invalid], strict=False)

    assert len(artifacts) == 1
    assert artifacts[0][1].request_id == "valid"


def test_compare_model_risk_baseline_detects_new_findings(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_result(baseline_path, _clean_request("Customer RAG", request_id="baseline"))
    _write_result(current_path, _request("Customer RAG", request_id="current"))

    comparison = compare_model_risk_baseline(
        baseline_path=baseline_path,
        current_path=current_path,
        baseline=load_single_model_risk_artifact(baseline_path),
        current=load_single_model_risk_artifact(current_path),
    )

    assert comparison.baseline_risk == "info"
    assert comparison.current_risk in {"high", "critical"}
    assert comparison.risk_score_delta > 0
    assert comparison.new_findings
    assert comparison.unaccepted_new_findings
    assert comparison.accepted_new_findings == []
    assert comparison.has_regression is True


def test_compare_model_risk_baseline_honors_accepted_fingerprints(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_result(baseline_path, _clean_request("Customer RAG", request_id="baseline-accepted"))
    _write_result(current_path, _request("Customer RAG", request_id="current-accepted"))
    current = load_single_model_risk_artifact(current_path)
    accepted = {
        fingerprint_model_risk_finding(current, finding)
        for finding in current.findings
    }

    comparison = compare_model_risk_baseline(
        baseline_path=baseline_path,
        current_path=current_path,
        baseline=load_single_model_risk_artifact(baseline_path),
        current=current,
        accepted_fingerprints=accepted,
    )

    assert comparison.new_findings
    assert comparison.accepted_new_findings
    assert comparison.unaccepted_new_findings == []
    assert comparison.has_regression is False


def test_render_model_risk_comparison_markdown_contains_delta_tables(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_result(baseline_path, _clean_request("Customer RAG", request_id="baseline-md"))
    _write_result(current_path, _request("Customer RAG", request_id="current-md"))
    comparison = compare_model_risk_baseline(
        baseline_path=baseline_path,
        current_path=current_path,
        baseline=load_single_model_risk_artifact(baseline_path),
        current=load_single_model_risk_artifact(current_path),
    )

    markdown = render_model_risk_comparison_markdown(comparison)

    assert "# AiSec Model-Risk Baseline Comparison" in markdown
    assert "## Unaccepted New Findings" in markdown
    assert "Regression: yes" in markdown
    assert "Customer RAG" in markdown


def test_evaluate_compare_cli_writes_json(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output = tmp_path / "comparison.json"
    _write_result(baseline_path, _clean_request("Customer RAG", request_id="baseline-json"))
    _write_result(current_path, _request("Customer RAG", request_id="current-json"))

    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "compare",
            "--baseline",
            str(baseline_path),
            "--current",
            str(current_path),
            "--output",
            str(output),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["target_name"] == "Customer RAG"
    assert data["has_regression"] is True
    assert data["new_findings"]


def test_evaluate_compare_cli_can_fail_on_regression(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output = tmp_path / "comparison.md"
    _write_result(baseline_path, _clean_request("Customer RAG", request_id="baseline-fail"))
    _write_result(current_path, _request("Customer RAG", request_id="current-fail"))

    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "compare",
            "--baseline",
            str(baseline_path),
            "--current",
            str(current_path),
            "--output",
            str(output),
            "--fail-on-regression",
        ],
    )

    assert result.exit_code == 1
    assert output.exists()
