"""``aisec evaluate`` commands for model-risk integrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from aisec.cli.console import console
from aisec.evaluation import (
    ModelRiskEvaluationRequest,
    ModelRiskEvaluationResult,
    compare_model_risk_baseline,
    discover_model_risk_artifacts,
    evaluate_model_risk,
    export_model_risk_framework_evidence,
    load_single_model_risk_artifact,
    load_model_risk_artifacts,
    summarize_model_risk_artifacts,
    write_model_risk_comparison,
    write_model_risk_framework_evidence,
    write_model_risk_summary,
)

evaluate_app = typer.Typer(help="Evaluate model, agent, and RAG risk descriptors.")


def _write_json(data: object, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = data.model_dump(mode="json") if hasattr(data, "model_dump") else data
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output.resolve()


@evaluate_app.command("model")
def evaluate_model(
    input_path: Annotated[Path, typer.Option("--input", "-i", help="Model-risk request JSON.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write the normalized evaluation result JSON."),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Override policy threshold: critical, high, medium, low, info, none.",
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Only write output, no summary table."),
    ] = False,
) -> None:
    """Evaluate a model/agent/RAG descriptor and return AiSec risk findings."""
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    if fail_on is not None:
        raw.setdefault("policy", {})["fail_on"] = fail_on
    request = ModelRiskEvaluationRequest.model_validate(raw)
    result = evaluate_model_risk(request)

    if output is None:
        output = Path("aisec-results") / f"model-risk-{request.request_id}.json"
    result_path = _write_json(result, output)

    if not quiet:
        table = Table(title="AiSec Model Risk Evaluation")
        table.add_column("Target")
        table.add_column("Risk")
        table.add_column("Score", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Verdict")
        table.add_row(
            result.target.name,
            result.overall_risk,
            f"{result.risk_score:.1f}",
            str(len(result.findings)),
            result.policy_verdict.status,
        )
        console.print(table)
        console.print(f"[success]Evaluation written to:[/success] {result_path}")

    if result.policy_verdict.status == "fail":
        raise typer.Exit(code=1)


@evaluate_app.command("schema")
def export_schema(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory where JSON Schema files will be written.",
        ),
    ] = Path("docs/schemas"),
) -> None:
    """Export JSON Schemas for the model-risk request/result protocol."""
    output_dir.mkdir(parents=True, exist_ok=True)
    schemas = {
        "model-risk-request.schema.json": ModelRiskEvaluationRequest.model_json_schema(),
        "model-risk-result.schema.json": ModelRiskEvaluationResult.model_json_schema(),
    }

    for filename, schema in schemas.items():
        path = output_dir / filename
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        console.print(f"[success]Wrote:[/success] {path.resolve()}")


@evaluate_app.command("summarize")
def summarize_artifacts(
    inputs: Annotated[
        list[Path],
        typer.Option(
            "--input",
            "-i",
            help="Model-risk result JSON file or directory containing result artifacts.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write summary artifact."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Summary format: markdown or json."),
    ] = "markdown",
    top_limit: Annotated[
        int,
        typer.Option("--top", help="Maximum number of top findings to include."),
    ] = 10,
    strict: Annotated[
        bool,
        typer.Option("--strict/--no-strict", help="Fail on invalid JSON files instead of skipping them."),
    ] = True,
) -> None:
    """Summarize model-risk result artifacts for CI comments and evidence."""
    if not inputs:
        raise typer.BadParameter("At least one --input path is required.")
    if output_format not in {"markdown", "json"}:
        raise typer.BadParameter("--format must be 'markdown' or 'json'.")

    paths = discover_model_risk_artifacts(inputs)
    artifacts = load_model_risk_artifacts(paths, strict=strict)
    summary = summarize_model_risk_artifacts(artifacts, top_limit=top_limit)

    if output is None:
        suffix = "md" if output_format == "markdown" else "json"
        output = Path("aisec-results") / f"model-risk-summary.{suffix}"
    summary_path = write_model_risk_summary(summary, output, output_format=output_format)

    table = Table(title="AiSec Model-Risk Artifact Summary")
    table.add_column("Artifacts", justify="right")
    table.add_column("Highest Risk")
    table.add_column("Worst Verdict")
    table.add_column("Findings", justify="right")
    table.add_row(
        str(summary.artifact_count),
        summary.highest_risk,
        summary.worst_policy_verdict,
        str(summary.total_findings),
    )
    console.print(table)
    console.print(f"[success]Summary written to:[/success] {summary_path}")

    if summary.worst_policy_verdict == "fail":
        raise typer.Exit(code=1)


@evaluate_app.command("evidence")
def export_framework_evidence(
    inputs: Annotated[
        list[Path],
        typer.Option(
            "--input",
            "-i",
            help="Model-risk result JSON file or directory containing result artifacts.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write framework evidence artifact."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Evidence format: markdown or json."),
    ] = "markdown",
    framework_filters: Annotated[
        list[str] | None,
        typer.Option("--framework", help="Limit export to a framework key such as gdpr or owasp_llm."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict/--no-strict", help="Fail on invalid JSON files instead of skipping them."),
    ] = True,
) -> None:
    """Export model-risk evidence grouped by governance framework."""
    if not inputs:
        raise typer.BadParameter("At least one --input path is required.")
    if output_format not in {"markdown", "json"}:
        raise typer.BadParameter("--format must be 'markdown' or 'json'.")

    paths = discover_model_risk_artifacts(inputs)
    artifacts = load_model_risk_artifacts(paths, strict=strict)
    export = export_model_risk_framework_evidence(
        artifacts,
        frameworks=set(framework_filters or []),
    )

    if output is None:
        suffix = "md" if output_format == "markdown" else "json"
        output = Path("aisec-results") / f"model-risk-framework-evidence.{suffix}"
    evidence_path = write_model_risk_framework_evidence(export, output, output_format=output_format)

    table = Table(title="AiSec Model-Risk Framework Evidence")
    table.add_column("Artifacts", justify="right")
    table.add_column("Frameworks", justify="right")
    table.add_column("Findings", justify="right")
    table.add_row(
        str(export.artifact_count),
        str(len(export.frameworks)),
        str(sum(report.finding_count for report in export.frameworks)),
    )
    console.print(table)
    console.print(f"[success]Framework evidence written to:[/success] {evidence_path}")


@evaluate_app.command("compare")
def compare_artifacts(
    baseline: Annotated[
        Path,
        typer.Option("--baseline", help="Approved baseline ModelRiskEvaluationResult JSON."),
    ],
    current: Annotated[
        Path,
        typer.Option("--current", help="Current ModelRiskEvaluationResult JSON."),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write comparison artifact."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Comparison format: markdown or json."),
    ] = "markdown",
    fail_on_regression: Annotated[
        bool,
        typer.Option(
            "--fail-on-regression/--no-fail-on-regression",
            help="Exit with code 1 when risk, verdict, or findings regress.",
        ),
    ] = False,
) -> None:
    """Compare a current model-risk result against an approved baseline."""
    if output_format not in {"markdown", "json"}:
        raise typer.BadParameter("--format must be 'markdown' or 'json'.")

    baseline_result = load_single_model_risk_artifact(baseline)
    current_result = load_single_model_risk_artifact(current)
    comparison = compare_model_risk_baseline(
        baseline_path=baseline.resolve(),
        current_path=current.resolve(),
        baseline=baseline_result,
        current=current_result,
    )

    if output is None:
        suffix = "md" if output_format == "markdown" else "json"
        output = Path("aisec-results") / f"model-risk-comparison.{suffix}"
    comparison_path = write_model_risk_comparison(comparison, output, output_format=output_format)

    table = Table(title="AiSec Model-Risk Baseline Comparison")
    table.add_column("Target")
    table.add_column("Baseline")
    table.add_column("Current")
    table.add_column("Delta", justify="right")
    table.add_column("New", justify="right")
    table.add_column("Resolved", justify="right")
    table.add_column("Regression")
    table.add_row(
        comparison.target_name,
        comparison.baseline_risk,
        comparison.current_risk,
        f"{comparison.risk_score_delta:+.1f}",
        str(len(comparison.new_findings)),
        str(len(comparison.resolved_findings)),
        "yes" if comparison.has_regression else "no",
    )
    console.print(table)
    console.print(f"[success]Comparison written to:[/success] {comparison_path}")

    if fail_on_regression and comparison.has_regression:
        raise typer.Exit(code=1)
