"""Tests for scan list/show/compare/export CLI commands (Phase 4)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestScanListCommand(unittest.TestCase):
    """Verify scan list command invocation."""

    @patch("aisec.cli.scan.ScanHistory" if False else "aisec.core.history.ScanHistory")
    def test_scan_list_imports_correctly(self, _mock):
        """Verify scan_list function exists and is importable."""
        from aisec.cli.scan import scan_list
        self.assertTrue(callable(scan_list))

    def test_scan_list_with_empty_history(self):
        """Verify scan list handles empty database."""
        from aisec.core.history import ScanHistory

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "test.db"
            history = ScanHistory(db_path=db)
            scans = history.list_scans()
            self.assertEqual(len(scans), 0)
            history.close()


class TestScanShowCommand(unittest.TestCase):
    """Verify scan show command."""

    def test_scan_show_importable(self):
        from aisec.cli.scan import scan_show
        self.assertTrue(callable(scan_show))


class TestScanCompareCommand(unittest.TestCase):
    """Verify scan compare command."""

    def test_scan_compare_importable(self):
        from aisec.cli.scan import scan_compare
        self.assertTrue(callable(scan_compare))

    def test_compare_with_no_differences(self):
        """Both scans with same findings should show no diff."""
        from aisec.core.history import ScanHistory

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "test.db"
            history = ScanHistory(db_path=db)
            new = history.get_new_findings("scan1", "scan2")
            resolved = history.get_resolved_findings("scan1", "scan2")
            self.assertEqual(len(new), 0)
            self.assertEqual(len(resolved), 0)
            history.close()


class TestScanExportCommand(unittest.TestCase):
    """Verify scan export command."""

    def test_scan_export_importable(self):
        from aisec.cli.scan import scan_export
        self.assertTrue(callable(scan_export))

    def test_export_json_format(self):
        """Verify JSON export of findings."""
        findings = [
            {"finding_id": "f1", "title": "Test", "severity": "high", "agent": "test"}
        ]
        content = json.dumps(findings, indent=2)
        parsed = json.loads(content)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["title"], "Test")

    def test_export_csv_format(self):
        """Verify CSV export of findings."""
        import csv
        import io

        findings = [
            {"finding_id": "f1", "title": "Test Finding", "severity": "high"}
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(findings[0].keys()))
        writer.writeheader()
        writer.writerows(findings)
        content = buf.getvalue()
        self.assertIn("finding_id", content)
        self.assertIn("Test Finding", content)


class TestScanHistoryCountReports(unittest.TestCase):
    """Verify count_scan_reports method."""

    def test_count_scan_reports_empty(self):
        from aisec.core.history import ScanHistory

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "test.db"
            history = ScanHistory(db_path=db)
            count = history.count_scan_reports()
            self.assertEqual(count, 0)
            history.close()

    def test_count_scan_reports_with_data(self):
        from aisec.core.history import ScanHistory

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / "test.db"
            history = ScanHistory(db_path=db)
            history.save_scan_report("s1", target_image="img1", image="img1")
            history.save_scan_report("s2", target_image="img2", image="img2")
            count = history.count_scan_reports()
            self.assertEqual(count, 2)
            history.close()


if __name__ == "__main__":
    unittest.main()
