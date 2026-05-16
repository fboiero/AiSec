from __future__ import annotations

from pathlib import Path


TEMPLATE = Path("docs/managed-pilot-report-template.md")


def test_managed_pilot_report_template_covers_go_no_go_sections() -> None:
    content = TEMPLATE.read_text(encoding="utf-8")

    assert "# AiSec Managed Pilot Report Template" in content
    assert "## Pilot Summary" in content
    assert "## Scope" in content
    assert "## Evidence Package" in content
    assert "## Smoke Result" in content
    assert "## Governance Checks" in content
    assert "## Findings And Exceptions" in content
    assert "## Rollback Readiness" in content
    assert "## Decision" in content
    assert "go / no-go / continue pilot" in content


def test_managed_pilot_report_template_references_required_artifacts() -> None:
    content = TEMPLATE.read_text(encoding="utf-8")

    for artifact in [
        "pre-smoke/live.json",
        "pre-smoke/ready.json",
        "pre-smoke/openapi.json",
        "pre-smoke/model-risk-rollup.json",
        "smoke.log",
        "post-smoke/model-risk-rollup.json",
        "post-smoke/model-risk-evaluations.json",
        "post-smoke/model-risk-baselines.json",
        "post-smoke/model-risk-exceptions.json",
    ]:
        assert artifact in content

    assert "evaluation_id" in content
    assert "policy_verdict.status" in content
    assert "OpenAPI includes model-risk endpoints" in content
    assert "Previous image tag known" in content


def test_managed_deployment_docs_link_pilot_report_template() -> None:
    managed = Path("docs/managed-deployment.md").read_text(encoding="utf-8")
    index = Path("docs/INDEX.md").read_text(encoding="utf-8")

    assert "managed-pilot-report-template.md" in managed
    assert "managed-pilot-report-template.md" in index
