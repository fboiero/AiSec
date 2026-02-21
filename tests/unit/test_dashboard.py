"""Tests for the TUI dashboard."""

import pytest

from aisec.cli.dashboard import ScanDashboard, _AgentStatus, _SEVERITY_STYLES
from aisec.core.context import ScanContext
from aisec.core.enums import Severity
from aisec.core.models import AgentResult, Finding


# ── AgentStatus dataclass ──────────────────────────────────────────

def test_agent_status_defaults():
    status = _AgentStatus(name="test")
    assert status.status == "pending"
    assert status.finding_count == 0
    assert status.started_at is None
    assert status.duration is None


# ── Severity styles ────────────────────────────────────────────────

def test_severity_styles_complete():
    """All Severity values should have a style."""
    for sev in Severity:
        assert sev in _SEVERITY_STYLES


# ── Dashboard construction ─────────────────────────────────────────

def test_dashboard_creates():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)
    assert dash._total_findings == 0
    assert dash._agents == {}


def test_dashboard_style_status():
    text = ScanDashboard._style_status("running")
    assert "RUNNING" in text.plain

    text_done = ScanDashboard._style_status("done")
    assert "DONE" in text_done.plain

    text_error = ScanDashboard._style_status("error")
    assert "ERROR" in text_error.plain


# ── Event handler behavior ─────────────────────────────────────────

def test_on_agent_started():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)
    dash._on_agent_started("network")
    assert "network" in dash._agents
    assert dash._agents["network"].status == "running"


def test_on_agent_completed():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)
    dash._on_agent_started("network")

    result = AgentResult(
        agent="network",
        findings=[Finding(title="test")],
        duration_seconds=1.5,
    )
    dash._on_agent_completed(result)
    assert dash._agents["network"].status == "done"
    assert dash._agents["network"].finding_count == 1
    assert dash._agents["network"].duration == 1.5


def test_on_agent_completed_with_error():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)

    result = AgentResult(
        agent="network",
        findings=[],
        duration_seconds=0.5,
        error="Connection refused",
    )
    dash._on_agent_completed(result)
    assert dash._agents["network"].status == "error"


def test_on_finding_new():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)

    finding = Finding(title="Test finding", severity=Severity.HIGH, agent="network")
    dash._on_finding_new(finding)
    assert dash._total_findings == 1
    assert len(dash._recent_findings) == 1
    assert dash._recent_findings[0]["title"] == "Test finding"
    assert dash._recent_findings[0]["severity"] == Severity.HIGH


def test_findings_capped_at_max():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)

    for i in range(15):
        finding = Finding(title=f"Finding {i}", severity=Severity.INFO, agent="test")
        dash._on_finding_new(finding)

    assert dash._total_findings == 15
    assert len(dash._recent_findings) <= 10


def test_set_agent_count():
    ctx = ScanContext(target_image="test:latest")
    dash = ScanDashboard(ctx)
    # Should not raise even when progress bar not yet created
    dash.set_agent_count(5)


# ── Layout building (smoke tests) ─────────────────────────────────

def test_build_layout_no_agents():
    ctx = ScanContext(target_image="test:latest", target_name="test")
    dash = ScanDashboard(ctx)
    layout = dash._build_layout()
    assert layout is not None


def test_build_layout_with_agents():
    ctx = ScanContext(target_image="test:latest", target_name="test")
    dash = ScanDashboard(ctx)
    dash._on_agent_started("network")
    result = AgentResult(agent="network", findings=[], duration_seconds=1.0)
    dash._on_agent_completed(result)
    layout = dash._build_layout()
    assert layout is not None
