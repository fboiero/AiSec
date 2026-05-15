"""Tests for CSV report renderer (Phase 5)."""

from __future__ import annotations

import csv
import io
import tempfile
import unittest
from pathlib import Path


class TestCsvRenderer(unittest.TestCase):
    """Verify CSV output format and structure."""

    def _make_report(self):
        """Create a minimal ScanReport for testing."""
        from aisec.core.models import ScanReport, ExecutiveSummary, Finding
        from aisec.core.enums import Severity

        findings = [
            Finding(
                title="Test Finding 1",
                severity=Severity.HIGH,
                agent="test-agent",
                description="A test finding",
                remediation="Fix it",
                cvss_score=7.5,
            ),
            Finding(
                title="Test Finding 2",
                severity=Severity.LOW,
                agent="other-agent",
                description="Another finding",
            ),
        ]

        return ScanReport(
            target_name="test-app",
            target_image="test-app:latest",
            aisec_version="1.10.0",
            executive_summary=ExecutiveSummary(total_findings=2, high_count=1, low_count=1),
            all_findings=findings,
        )

    def test_render_creates_file(self):
        from aisec.reports.renderers.csv_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.csv"
            result = render(report, output)
            self.assertTrue(result.exists())

    def test_render_has_header_row(self):
        from aisec.reports.renderers.csv_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.csv"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            reader = csv.reader(io.StringIO(content))
            header = next(reader)
            self.assertIn("title", header)
            self.assertIn("severity", header)
            self.assertIn("agent", header)

    def test_render_has_correct_row_count(self):
        from aisec.reports.renderers.csv_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.csv"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)
            # 1 header + 2 data rows
            self.assertEqual(len(rows), 3)

    def test_render_contains_finding_data(self):
        from aisec.reports.renderers.csv_renderer import render

        report = self._make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.csv"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            self.assertIn("Test Finding 1", content)
            self.assertIn("high", content)
            self.assertIn("test-agent", content)

    def test_render_empty_findings(self):
        from aisec.reports.renderers.csv_renderer import render
        from aisec.core.models import ScanReport

        report = ScanReport(target_name="empty", target_image="empty:latest")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "test.csv"
            render(report, output)
            content = output.read_text(encoding="utf-8")
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)
            self.assertEqual(len(rows), 1)  # header only


if __name__ == "__main__":
    unittest.main()
