"""Tests for ReportBuilder."""

from aisec.core.context import ScanContext
from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding
from aisec.reports.builder import ReportBuilder


def test_build_empty_report(scan_context):
    builder = ReportBuilder()
    report = builder.build(scan_context)
    assert report.target_name == scan_context.target_name
    assert report.executive_summary.total_findings == 0
    assert report.executive_summary.overall_risk_level == Severity.INFO


def test_build_with_findings(scan_context, sample_findings):
    scan_context.agent_results["test"] = AgentResult(
        agent="test", findings=sample_findings, duration_seconds=1.0
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)

    assert report.executive_summary.total_findings == len(sample_findings)
    assert report.executive_summary.critical_count == 1
    assert report.executive_summary.high_count == 1
    assert report.executive_summary.overall_risk_level == Severity.CRITICAL
    assert len(report.all_findings) == len(sample_findings)


def test_build_deduplicates(scan_context):
    dup_finding = Finding(title="Same Issue", severity=Severity.HIGH, agent="a")
    scan_context.agent_results["agent_a"] = AgentResult(
        agent="agent_a", findings=[dup_finding]
    )
    scan_context.agent_results["agent_b"] = AgentResult(
        agent="agent_b",
        findings=[Finding(title="Same Issue", severity=Severity.HIGH, agent="b")],
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)
    assert report.executive_summary.total_findings == 1


def test_build_owasp_mapping(scan_context):
    findings = [
        Finding(
            title="Injection",
            severity=Severity.CRITICAL,
            agent="test",
            owasp_llm=["LLM01"],
            owasp_agentic=["ASI01"],
            nist_ai_rmf=["MEASURE"],
        )
    ]
    scan_context.agent_results["test"] = AgentResult(
        agent="test", findings=findings
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)

    assert "LLM01" in report.owasp_llm_findings
    assert "ASI01" in report.owasp_agentic_findings
    assert "MEASURE" in report.nist_ai_rmf_findings


def test_build_compliance_gdpr_fail(scan_context):
    findings = [
        Finding(
            title="Data Leak",
            severity=Severity.HIGH,
            agent="test",
            owasp_llm=["LLM02"],
        )
    ]
    scan_context.agent_results["test"] = AgentResult(
        agent="test", findings=findings
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)

    gdpr = report.compliance.gdpr
    assert gdpr.failed > 0


def test_build_compliance_clean(scan_context):
    # No findings = all compliance checks should pass
    builder = ReportBuilder()
    report = builder.build(scan_context)

    gdpr = report.compliance.gdpr
    assert gdpr.failed == 0
    assert gdpr.passed >= 1


def test_build_ai_risk_scores(scan_context, sample_findings):
    scan_context.agent_results["test"] = AgentResult(
        agent="test", findings=sample_findings
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)

    for finding in report.all_findings:
        assert finding.ai_risk_score is not None
        assert 0.0 <= finding.ai_risk_score <= 10.0


def test_build_top_risks(scan_context, sample_findings):
    scan_context.agent_results["test"] = AgentResult(
        agent="test", findings=sample_findings
    )
    builder = ReportBuilder()
    report = builder.build(scan_context)

    top = report.executive_summary.top_risks
    assert len(top) <= 5
    # First top risk should be the critical one
    assert "Critical" in top[0] or "Prompt" in top[0]
