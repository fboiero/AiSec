"""Tests for core domain models."""

from aisec.core.enums import FindingStatus, Severity
from aisec.core.models import (
    AgentResult,
    ComplianceChecklist,
    Evidence,
    ExecutiveSummary,
    Finding,
    RiskOverview,
    ScanReport,
)


def test_finding_defaults():
    f = Finding()
    assert f.severity == Severity.INFO
    assert f.status == FindingStatus.OPEN
    assert f.owasp_llm == []
    assert f.evidence == []
    assert f.id is not None


def test_finding_with_values(sample_finding):
    assert sample_finding.title == "Test Finding"
    assert sample_finding.severity == Severity.MEDIUM
    assert "LLM01" in sample_finding.owasp_llm
    assert len(sample_finding.evidence) == 1


def test_evidence_creation():
    e = Evidence(type="network_capture", summary="Captured packet", location="/tmp/cap.pcap")
    assert e.type == "network_capture"
    assert e.raw_data == ""


def test_agent_result():
    r = AgentResult(agent="test", findings=[], duration_seconds=1.5)
    assert r.agent == "test"
    assert r.error is None


def test_risk_overview_defaults():
    r = RiskOverview()
    assert r.ai_risk_score == 0.0
    assert r.compliance_score == 0.0


def test_executive_summary():
    s = ExecutiveSummary(
        overall_risk_level=Severity.HIGH,
        total_findings=5,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=1,
        info_count=1,
    )
    assert s.total_findings == 5


def test_compliance_checklist():
    c = ComplianceChecklist(
        framework_name="GDPR",
        total_checks=10,
        passed=7,
        failed=2,
        not_applicable=1,
    )
    assert c.passed + c.failed + c.not_applicable == c.total_checks


def test_scan_report_defaults():
    r = ScanReport()
    assert r.language == "en"
    assert r.all_findings == []
