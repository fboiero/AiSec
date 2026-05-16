"""Utilities for summarizing model-risk evaluation artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aisec.core.enums import Severity
from aisec.evaluation.models import ModelRiskEvaluationResult

RISK_ORDER = ("critical", "high", "medium", "low", "info")
VERDICT_ORDER = ("fail", "warn", "pass")


class ModelRiskArtifactTarget(BaseModel):
    """Per-artifact summary used by CI adapters and comments."""

    path: str
    request_id: str
    evaluation_id: str
    target_name: str
    target_type: str
    provider: str = ""
    model_id: str = ""
    overall_risk: str
    risk_score: float
    policy_verdict: str
    finding_count: int


class ModelRiskArtifactSummary(BaseModel):
    """Rollup across one or more model-risk result artifacts."""

    artifact_count: int
    highest_risk: str = "info"
    worst_policy_verdict: str = "pass"
    total_findings: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    policy_counts: dict[str, int] = Field(default_factory=dict)
    risk_counts: dict[str, int] = Field(default_factory=dict)
    framework_counts: dict[str, int] = Field(default_factory=dict)
    targets: list[ModelRiskArtifactTarget] = Field(default_factory=list)
    top_findings: list[dict[str, str]] = Field(default_factory=list)


class ModelRiskFindingDelta(BaseModel):
    """Finding that appeared, disappeared, or remained across a baseline."""

    fingerprint: str
    title: str
    severity: str
    frameworks: list[str] = Field(default_factory=list)
    target_name: str


class ModelRiskFrameworkFindingEvidence(BaseModel):
    """Finding evidence normalized for a framework-specific export."""

    target_name: str
    request_id: str
    evaluation_id: str
    finding_id: str
    title: str
    severity: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""


class ModelRiskFrameworkReport(BaseModel):
    """Evidence packet for one governance framework."""

    framework: str
    status_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    target_names: list[str] = Field(default_factory=list)
    finding_count: int = 0
    findings: list[ModelRiskFrameworkFindingEvidence] = Field(default_factory=list)


class ModelRiskFrameworkEvidenceExport(BaseModel):
    """Framework-grouped evidence export across model-risk artifacts."""

    artifact_count: int
    frameworks: list[ModelRiskFrameworkReport] = Field(default_factory=list)


class ModelRiskBaselineComparison(BaseModel):
    """Comparison between one current result and one approved baseline."""

    baseline_path: str
    current_path: str
    baseline_request_id: str
    current_request_id: str
    target_name: str
    baseline_risk: str
    current_risk: str
    baseline_risk_score: float
    current_risk_score: float
    risk_score_delta: float
    baseline_policy_verdict: str
    current_policy_verdict: str
    new_findings: list[ModelRiskFindingDelta] = Field(default_factory=list)
    accepted_new_findings: list[ModelRiskFindingDelta] = Field(default_factory=list)
    unaccepted_new_findings: list[ModelRiskFindingDelta] = Field(default_factory=list)
    resolved_findings: list[ModelRiskFindingDelta] = Field(default_factory=list)
    unchanged_findings: list[ModelRiskFindingDelta] = Field(default_factory=list)
    risk_regressed: bool = False
    policy_regressed: bool = False
    has_regression: bool = False


def discover_model_risk_artifacts(inputs: list[Path]) -> list[Path]:
    """Return JSON files from input files or directories in stable order."""
    discovered: list[Path] = []
    for input_path in inputs:
        if input_path.is_dir():
            discovered.extend(sorted(input_path.rglob("*.json")))
        elif input_path.is_file():
            discovered.append(input_path)
        else:
            raise FileNotFoundError(f"Model-risk artifact input not found: {input_path}")
    return sorted(dict.fromkeys(path.resolve() for path in discovered))


def load_model_risk_artifacts(paths: list[Path], *, strict: bool = True) -> list[tuple[Path, ModelRiskEvaluationResult]]:
    """Load and validate model-risk result artifacts."""
    artifacts: list[tuple[Path, ModelRiskEvaluationResult]] = []
    errors: list[str] = []
    for path in paths:
        try:
            result = ModelRiskEvaluationResult.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - returned as artifact parse context.
            if strict:
                errors.append(f"{path}: {exc}")
            continue
        artifacts.append((path, result))

    if errors:
        joined = "\n".join(errors)
        raise ValueError(f"Invalid model-risk artifact(s):\n{joined}")
    if not artifacts:
        raise ValueError("No valid model-risk result artifacts found.")
    return artifacts


def load_single_model_risk_artifact(path: Path) -> ModelRiskEvaluationResult:
    """Load exactly one model-risk result artifact."""
    artifacts = load_model_risk_artifacts([path], strict=True)
    return artifacts[0][1]


def summarize_model_risk_artifacts(
    artifacts: list[tuple[Path, ModelRiskEvaluationResult]],
    *,
    top_limit: int = 10,
) -> ModelRiskArtifactSummary:
    """Build a deterministic rollup for CI comments and artifacts."""
    severity_counts = {severity.value: 0 for severity in Severity}
    policy_counts = {verdict: 0 for verdict in VERDICT_ORDER}
    risk_counts = {risk: 0 for risk in RISK_ORDER}
    framework_counts: dict[str, int] = {}
    targets: list[ModelRiskArtifactTarget] = []
    top_findings: list[dict[str, str]] = []

    highest_risk = "info"
    worst_policy_verdict = "pass"

    for path, result in artifacts:
        risk_counts[result.overall_risk] += 1
        policy_counts[result.policy_verdict.status] += 1
        highest_risk = _min_ordered(highest_risk, result.overall_risk, RISK_ORDER)
        worst_policy_verdict = _min_ordered(worst_policy_verdict, result.policy_verdict.status, VERDICT_ORDER)

        targets.append(
            ModelRiskArtifactTarget(
                path=str(path),
                request_id=result.request_id,
                evaluation_id=result.evaluation_id,
                target_name=result.target.name,
                target_type=result.target.type,
                provider=result.target.provider,
                model_id=result.target.model_id,
                overall_risk=result.overall_risk,
                risk_score=result.risk_score,
                policy_verdict=result.policy_verdict.status,
                finding_count=len(result.findings),
            )
        )

        for framework in result.frameworks:
            framework_counts[framework.framework] = framework_counts.get(framework.framework, 0) + framework.finding_count

        for finding in result.findings:
            severity_counts[finding.severity.value] += 1
            top_findings.append(
                {
                    "target": result.target.name,
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "frameworks": ", ".join(finding.frameworks),
                }
            )

    top_findings.sort(key=lambda item: (RISK_ORDER.index(item["severity"]), item["target"], item["title"]))
    framework_counts = dict(sorted(framework_counts.items()))

    return ModelRiskArtifactSummary(
        artifact_count=len(artifacts),
        highest_risk=highest_risk,
        worst_policy_verdict=worst_policy_verdict,
        total_findings=sum(severity_counts.values()),
        severity_counts=severity_counts,
        policy_counts=policy_counts,
        risk_counts=risk_counts,
        framework_counts=framework_counts,
        targets=targets,
        top_findings=top_findings[:top_limit],
    )


def export_model_risk_framework_evidence(
    artifacts: list[tuple[Path, ModelRiskEvaluationResult]],
    *,
    frameworks: set[str] | None = None,
) -> ModelRiskFrameworkEvidenceExport:
    """Group model-risk findings and evidence by compliance framework."""
    reports: dict[str, ModelRiskFrameworkReport] = {}
    requested_frameworks = frameworks or set()

    for _path, result in artifacts:
        for framework_result in result.frameworks:
            if requested_frameworks and framework_result.framework not in requested_frameworks:
                continue
            report = reports.setdefault(
                framework_result.framework,
                ModelRiskFrameworkReport(
                    framework=framework_result.framework,
                    status_counts={verdict: 0 for verdict in VERDICT_ORDER},
                    severity_counts={severity.value: 0 for severity in Severity},
                ),
            )
            report.status_counts[framework_result.status] = report.status_counts.get(framework_result.status, 0) + 1
            if result.target.name not in report.target_names:
                report.target_names.append(result.target.name)

        for finding in result.findings:
            for framework in finding.frameworks:
                if requested_frameworks and framework not in requested_frameworks:
                    continue
                report = reports.setdefault(
                    framework,
                    ModelRiskFrameworkReport(
                        framework=framework,
                        status_counts={verdict: 0 for verdict in VERDICT_ORDER},
                        severity_counts={severity.value: 0 for severity in Severity},
                    ),
                )
                if result.target.name not in report.target_names:
                    report.target_names.append(result.target.name)
                report.severity_counts[finding.severity.value] = report.severity_counts.get(finding.severity.value, 0) + 1
                report.findings.append(
                    ModelRiskFrameworkFindingEvidence(
                        target_name=result.target.name,
                        request_id=result.request_id,
                        evaluation_id=result.evaluation_id,
                        finding_id=finding.id,
                        title=finding.title,
                        severity=finding.severity.value,
                        evidence=[evidence.summary for evidence in finding.evidence],
                        remediation=finding.remediation,
                    )
                )

    for report in reports.values():
        report.target_names = sorted(report.target_names)
        report.findings.sort(
            key=lambda finding: (
                RISK_ORDER.index(finding.severity),
                finding.target_name,
                finding.title,
            )
        )
        report.finding_count = len(report.findings)

    return ModelRiskFrameworkEvidenceExport(
        artifact_count=len(artifacts),
        frameworks=sorted(reports.values(), key=lambda report: report.framework),
    )


def compare_model_risk_baseline(
    *,
    baseline_path: Path,
    current_path: Path,
    baseline: ModelRiskEvaluationResult,
    current: ModelRiskEvaluationResult,
    accepted_fingerprints: set[str] | None = None,
) -> ModelRiskBaselineComparison:
    """Compare current model-risk evidence against an approved baseline."""
    accepted_fingerprints = accepted_fingerprints or set()
    baseline_findings = {
        fingerprint_model_risk_finding(baseline, finding): finding
        for finding in baseline.findings
    }
    current_findings = {
        fingerprint_model_risk_finding(current, finding): finding
        for finding in current.findings
    }

    new_keys = sorted(set(current_findings) - set(baseline_findings), key=_fingerprint_sort_key)
    accepted_new_keys = [key for key in new_keys if key in accepted_fingerprints]
    unaccepted_new_keys = [key for key in new_keys if key not in accepted_fingerprints]
    resolved_keys = sorted(set(baseline_findings) - set(current_findings), key=_fingerprint_sort_key)
    unchanged_keys = sorted(set(current_findings) & set(baseline_findings), key=_fingerprint_sort_key)

    risk_regressed = RISK_ORDER.index(current.overall_risk) < RISK_ORDER.index(baseline.overall_risk)
    policy_regressed = VERDICT_ORDER.index(current.policy_verdict.status) < VERDICT_ORDER.index(baseline.policy_verdict.status)
    has_regression = bool(unaccepted_new_keys) or ((risk_regressed or policy_regressed) and not new_keys)

    return ModelRiskBaselineComparison(
        baseline_path=str(baseline_path),
        current_path=str(current_path),
        baseline_request_id=baseline.request_id,
        current_request_id=current.request_id,
        target_name=current.target.name,
        baseline_risk=baseline.overall_risk,
        current_risk=current.overall_risk,
        baseline_risk_score=baseline.risk_score,
        current_risk_score=current.risk_score,
        risk_score_delta=round(current.risk_score - baseline.risk_score, 1),
        baseline_policy_verdict=baseline.policy_verdict.status,
        current_policy_verdict=current.policy_verdict.status,
        new_findings=[_finding_delta(current.target.name, current_findings[key], key) for key in new_keys],
        accepted_new_findings=[
            _finding_delta(current.target.name, current_findings[key], key)
            for key in accepted_new_keys
        ],
        unaccepted_new_findings=[
            _finding_delta(current.target.name, current_findings[key], key)
            for key in unaccepted_new_keys
        ],
        resolved_findings=[_finding_delta(baseline.target.name, baseline_findings[key], key) for key in resolved_keys],
        unchanged_findings=[_finding_delta(current.target.name, current_findings[key], key) for key in unchanged_keys],
        risk_regressed=risk_regressed,
        policy_regressed=policy_regressed,
        has_regression=has_regression,
    )


def render_model_risk_comparison_markdown(comparison: ModelRiskBaselineComparison) -> str:
    """Render baseline comparison as Markdown for PR/MR comments."""
    lines = [
        "# AiSec Model-Risk Baseline Comparison",
        "",
        f"- Target: {comparison.target_name}",
        f"- Baseline risk: {comparison.baseline_risk}",
        f"- Current risk: {comparison.current_risk}",
        f"- Risk score delta: {comparison.risk_score_delta:+.1f}",
        f"- Baseline verdict: {comparison.baseline_policy_verdict}",
        f"- Current verdict: {comparison.current_policy_verdict}",
        f"- New findings: {len(comparison.new_findings)}",
        f"- Accepted new findings: {len(comparison.accepted_new_findings)}",
        f"- Unaccepted new findings: {len(comparison.unaccepted_new_findings)}",
        f"- Resolved findings: {len(comparison.resolved_findings)}",
        f"- Regression: {'yes' if comparison.has_regression else 'no'}",
        "",
    ]

    lines.extend(_delta_table("Unaccepted New Findings", comparison.unaccepted_new_findings))
    lines.extend(_delta_table("Accepted New Findings", comparison.accepted_new_findings))
    lines.extend(_delta_table("Resolved Findings", comparison.resolved_findings))
    return "\n".join(lines) + "\n"


def write_model_risk_comparison(
    comparison: ModelRiskBaselineComparison,
    output: Path,
    *,
    output_format: str,
) -> Path:
    """Write a model-risk baseline comparison as Markdown or JSON."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        output.write_text(
            json.dumps(comparison.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    elif output_format == "markdown":
        output.write_text(render_model_risk_comparison_markdown(comparison), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported comparison format: {output_format}")
    return output.resolve()


def render_model_risk_summary_markdown(summary: ModelRiskArtifactSummary) -> str:
    """Render a concise Markdown summary for PR/MR comments or CI artifacts."""
    lines = [
        "# AiSec Model-Risk Summary",
        "",
        f"- Artifacts: {summary.artifact_count}",
        f"- Highest risk: {summary.highest_risk}",
        f"- Worst policy verdict: {summary.worst_policy_verdict}",
        f"- Total findings: {summary.total_findings}",
        "",
        "## Severity Counts",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in RISK_ORDER:
        lines.append(f"| {severity} | {summary.severity_counts.get(severity, 0)} |")

    lines.extend(
        [
            "",
            "## Targets",
            "",
            "| Target | Type | Provider | Model | Risk | Score | Verdict | Findings |",
            "| --- | --- | --- | --- | --- | ---: | --- | ---: |",
        ]
    )
    for target in summary.targets:
        lines.append(
            "| "
            f"{_md(target.target_name)} | "
            f"{target.target_type} | "
            f"{_md(target.provider)} | "
            f"{_md(target.model_id)} | "
            f"{target.overall_risk} | "
            f"{target.risk_score:.1f} | "
            f"{target.policy_verdict} | "
            f"{target.finding_count} |"
        )

    if summary.top_findings:
        lines.extend(
            [
                "",
                "## Top Findings",
                "",
                "| Severity | Target | Finding | Frameworks |",
                "| --- | --- | --- | --- |",
            ]
        )
        for finding in summary.top_findings:
            lines.append(
                "| "
                f"{finding['severity']} | "
                f"{_md(finding['target'])} | "
                f"{_md(finding['title'])} | "
                f"{_md(finding['frameworks'])} |"
            )

    return "\n".join(lines) + "\n"


def write_model_risk_summary(summary: ModelRiskArtifactSummary, output: Path, *, output_format: str) -> Path:
    """Write a model-risk artifact summary as Markdown or JSON."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        payload: dict[str, Any] = summary.model_dump(mode="json")
        output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    elif output_format == "markdown":
        output.write_text(render_model_risk_summary_markdown(summary), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported summary format: {output_format}")
    return output.resolve()


def render_model_risk_framework_evidence_markdown(export: ModelRiskFrameworkEvidenceExport) -> str:
    """Render framework evidence as Markdown for compliance reviews."""
    lines = [
        "# AiSec Framework Evidence Export",
        "",
        f"- Artifacts: {export.artifact_count}",
        f"- Frameworks: {len(export.frameworks)}",
        "",
    ]

    for report in export.frameworks:
        lines.extend(
            [
                f"## {report.framework}",
                "",
                f"- Targets: {', '.join(_md(target) for target in report.target_names) if report.target_names else '-'}",
                f"- Findings: {report.finding_count}",
                "",
                "| Severity | Count |",
                "| --- | ---: |",
            ]
        )
        for severity in RISK_ORDER:
            lines.append(f"| {severity} | {report.severity_counts.get(severity, 0)} |")

        lines.extend(["", "| Severity | Target | Finding | Evidence |", "| --- | --- | --- | --- |"])
        if report.findings:
            for finding in report.findings:
                evidence = "; ".join(finding.evidence) if finding.evidence else "-"
                lines.append(
                    "| "
                    f"{finding.severity} | "
                    f"{_md(finding.target_name)} | "
                    f"{_md(finding.title)} | "
                    f"{_md(evidence)} |"
                )
        else:
            lines.append("| - | - | No findings. | - |")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_model_risk_framework_evidence(
    export: ModelRiskFrameworkEvidenceExport,
    output: Path,
    *,
    output_format: str,
) -> Path:
    """Write framework evidence as Markdown or JSON."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "json":
        output.write_text(
            json.dumps(export.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    elif output_format == "markdown":
        output.write_text(render_model_risk_framework_evidence_markdown(export), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported framework evidence format: {output_format}")
    return output.resolve()


def _min_ordered(current: str, candidate: str, order: tuple[str, ...]) -> str:
    return candidate if order.index(candidate) < order.index(current) else current


def fingerprint_model_risk_finding(result: ModelRiskEvaluationResult, finding: Any) -> str:
    """Return a stable finding fingerprint across request IDs."""
    frameworks = ",".join(sorted(finding.frameworks))
    return "|".join(
        [
            result.target.name.strip().lower(),
            finding.severity.value,
            finding.title.strip().lower(),
            frameworks,
        ]
    )


def _fingerprint_sort_key(fingerprint: str) -> tuple[int, str]:
    parts = fingerprint.split("|")
    severity = parts[1] if len(parts) > 1 else "info"
    return (RISK_ORDER.index(severity), fingerprint)


def _finding_delta(target_name: str, finding: Any, fingerprint: str) -> ModelRiskFindingDelta:
    return ModelRiskFindingDelta(
        fingerprint=fingerprint,
        title=finding.title,
        severity=finding.severity.value,
        frameworks=finding.frameworks,
        target_name=target_name,
    )


def _delta_table(title: str, findings: list[ModelRiskFindingDelta]) -> list[str]:
    lines = [f"## {title}", ""]
    if not findings:
        lines.extend(["No findings.", ""])
        return lines
    lines.extend(["| Severity | Target | Finding | Frameworks |", "| --- | --- | --- | --- |"])
    for finding in findings:
        lines.append(
            "| "
            f"{finding.severity} | "
            f"{_md(finding.target_name)} | "
            f"{_md(finding.title)} | "
            f"{_md(', '.join(finding.frameworks))} |"
        )
    lines.append("")
    return lines


def _md(value: str) -> str:
    return value.replace("|", "\\|") if value else "-"
