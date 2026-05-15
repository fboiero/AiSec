"""Tests for Markdown report renderer (Phase 5)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class TestMdRenderer(unittest.TestCase):
    """Verify Markdown output structure and content."""

    def _make_report(self):
        """Create a minimal ScanReport for testing."""
        from aisec.core.models import (
            ScanReport, ExecutiveSummary, RiskOverview, Finding, AgentResult,
        )
        from aisec.core.enums import Severity

        findings = [
            Finding(
                title="Prompt Injection Risk",
                severity=Severity.CRITICAL,
                agent="prompt-security",
                description="Direct prompt injection vulnerability detected.",
                remediation="Add input sanitization.",
                cvss_score=9.0,
                ai_risk_score=8.5,
            ),
            Finding(
                title="Weak Key",
                severity=Severity.MEDIUM,
                agent="crypto-audit",
                description="RSA key shorter than 2048 bits.",
            ),
        ]

        agent_results = {
            "prompt-security": AgentResult(
                agent="prompt-security",
                findings=[findings[0]],
                duration_seconds=1.2,
            ),
            "crypto-audit": AgentResult(
                agent="crypto-audit",
                findings=[findings[1]],
                duration_seconds=0.5,
            ),
        }

        return ScanReport(
            target_name="test-app",
            target_image="test-app:latest",
            aisec_version="1.10.0",
            scan_duration_seconds=5.0,
            executive_summary=ExecutiveSummary(
                total_findings=2,
                critical_count=1,
                medium_count=1,
                overall_risk_level=Severity.CRITICAL,
                top_risks=["Prompt injection", "Weak cryptography"],
            ),
            risk_overview=RiskOverview(
                ai_risk_score=8.0,
                compliance_score=75.0,
            ),
            all_findings=findings,
            agent_results=agent_results,
        )

    def test_render_creates_file(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            result = render(report, output)
            self.assertTrue(result.exists())

    def test_render_contains_title(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("# AiSec Security Report: test-app", content)

    def test_render_contains_executive_summary(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("## Executive Summary", content)
            self.assertIn("**Total Findings:** 2", content)

    def test_render_contains_risk_overview(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("## Risk Overview", content)
            self.assertIn("AI Risk Score", content)

    def test_render_contains_findings_by_agent(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("## Findings by Agent", content)
            self.assertIn("prompt-security", content)
            self.assertIn("crypto-audit", content)

    def test_render_contains_all_findings(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("Prompt Injection Risk", content)
            self.assertIn("Weak Key", content)

    def test_render_contains_top_risks(self):
        from aisec.reports.renderers.md_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.md"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("Prompt injection", content)


if __name__ == "__main__":
    unittest.main()
