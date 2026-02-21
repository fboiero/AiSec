"""Tests for report renderers."""

import json
from pathlib import Path

from aisec.core.enums import Severity
from aisec.core.models import (
    AgentResult,
    ExecutiveSummary,
    Finding,
    RiskOverview,
    ScanReport,
)
from aisec.reports.renderers import html_renderer, json_renderer


def _make_report() -> ScanReport:
    """Create a minimal scan report for renderer tests."""
    findings = [
        Finding(
            title="Test Finding",
            description="A test finding",
            severity=Severity.HIGH,
            agent="test_agent",
            owasp_llm=["LLM01"],
            remediation="Fix it.",
        )
    ]
    return ScanReport(
        target_name="test-target",
        target_image="test:latest",
        aisec_version="0.1.0",
        language="en",
        executive_summary=ExecutiveSummary(
            overall_risk_level=Severity.HIGH,
            total_findings=1,
            high_count=1,
            summary_text="1 high finding.",
        ),
        risk_overview=RiskOverview(ai_risk_score=70.0),
        agent_results={"test_agent": AgentResult(agent="test_agent", findings=findings)},
        all_findings=findings,
    )


def test_json_renderer(tmp_path: Path):
    report = _make_report()
    output = json_renderer.render(report, tmp_path / "report.json")
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["target_name"] == "test-target"
    assert data["aisec_version"] == "0.1.0"
    assert len(data["all_findings"]) == 1
    assert data["all_findings"][0]["title"] == "Test Finding"


def test_json_renderer_creates_dirs(tmp_path: Path):
    report = _make_report()
    nested = tmp_path / "deep" / "nested" / "dir"
    output = json_renderer.render(report, nested / "report.json")
    assert output.exists()


def test_html_renderer(tmp_path: Path):
    report = _make_report()
    output = html_renderer.render(report, tmp_path / "report.html")
    assert output.exists()
    html = output.read_text()
    assert "AiSec" in html
    assert "test-target" in html
    assert "Test Finding" in html


def test_html_renderer_fallback(tmp_path: Path):
    """When no template dir exists, fallback template should be used."""
    report = _make_report()
    output = html_renderer.render(
        report, tmp_path / "report.html", template_dir=tmp_path / "nonexistent"
    )
    assert output.exists()
    html = output.read_text()
    assert "AiSec" in html


def test_html_renderer_spanish(tmp_path: Path):
    report = _make_report()
    report.language = "es"
    output = html_renderer.render(report, tmp_path / "report_es.html")
    assert output.exists()


def test_json_renderer_handles_enums(tmp_path: Path):
    report = _make_report()
    output = json_renderer.render(report, tmp_path / "report.json")
    data = json.loads(output.read_text())
    # Severity should be serialized as string value
    assert data["executive_summary"]["overall_risk_level"] in ("critical", "high", "medium", "low", "info")


def test_json_renderer_handles_uuid(tmp_path: Path):
    report = _make_report()
    output = json_renderer.render(report, tmp_path / "report.json")
    data = json.loads(output.read_text())
    # UUIDs should be serialized as strings
    assert isinstance(data["scan_id"], str)
    assert len(data["scan_id"]) == 36  # UUID format
