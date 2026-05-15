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
    evaluate_model_risk,
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
