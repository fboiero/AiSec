"""Tests for scan report persistence in ScanHistory."""

import json

import pytest

from aisec.core.history import ScanHistory


@pytest.fixture
def history(tmp_path):
    db = ScanHistory(db_path=tmp_path / "test.db")
    yield db
    db.close()


class TestScanReportTable:
    def test_table_exists(self, history):
        conn = history._get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_reports'"
        ).fetchone()
        assert row is not None

    def test_index_exists(self, history):
        conn = history._get_conn()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_scan_reports%'"
        ).fetchall()
        names = [r["name"] for r in rows]
        assert "idx_scan_reports_status" in names
        assert "idx_scan_reports_target" in names


class TestSaveScanReport:
    def test_save_pending(self, history):
        sid = history.save_scan_report("s-001", "myapp:latest")
        assert sid == "s-001"
        report = history.get_scan_report("s-001")
        assert report is not None
        assert report["status"] == "pending"
        assert report["target_image"] == "myapp:latest"

    def test_save_returns_scan_id(self, history):
        result = history.save_scan_report("s-002", "app:v2", image="app:v2")
        assert result == "s-002"


class TestUpdateScanReport:
    def test_update_status_to_running(self, history):
        history.save_scan_report("s-001", "app:latest")
        updated = history.update_scan_report("s-001", status="running")
        assert updated is True
        report = history.get_scan_report("s-001")
        assert report["status"] == "running"

    def test_update_completed_with_report(self, history):
        history.save_scan_report("s-001", "app:latest")
        report_data = json.dumps({"findings": [{"title": "test"}]})
        history.update_scan_report(
            "s-001", status="completed", report_json=report_data, finding_count=1
        )
        report = history.get_scan_report("s-001")
        assert report["status"] == "completed"
        assert report["completed_at"] is not None
        assert report["report"] == {"findings": [{"title": "test"}]}
        assert report["finding_count"] == 1

    def test_update_failed_with_error(self, history):
        history.save_scan_report("s-001", "app:latest")
        history.update_scan_report(
            "s-001", status="failed", error_message="Docker timeout"
        )
        report = history.get_scan_report("s-001")
        assert report["status"] == "failed"
        assert report["error_message"] == "Docker timeout"
        assert report["completed_at"] is not None

    def test_update_nonexistent_returns_false(self, history):
        result = history.update_scan_report("no-exist", status="running")
        assert result is False


class TestGetScanReport:
    def test_get_existing(self, history):
        history.save_scan_report("s-001", "app:latest")
        report = history.get_scan_report("s-001")
        assert report is not None
        assert report["scan_id"] == "s-001"

    def test_get_with_report_json_parsed(self, history):
        history.save_scan_report("s-001", "app:latest")
        history.update_scan_report(
            "s-001", status="completed", report_json='{"key": "value"}'
        )
        report = history.get_scan_report("s-001")
        assert report["report"] == {"key": "value"}

    def test_get_nonexistent_returns_none(self, history):
        assert history.get_scan_report("no-exist") is None


class TestListScanReports:
    def test_list_empty(self, history):
        assert history.list_scan_reports() == []

    def test_list_ordered_by_date(self, history):
        history.save_scan_report("s-001", "app1:latest")
        history.save_scan_report("s-002", "app2:latest")
        reports = history.list_scan_reports()
        assert len(reports) == 2
        # Most recent first
        assert reports[0]["scan_id"] == "s-002"

    def test_list_with_limit_offset(self, history):
        for i in range(5):
            history.save_scan_report(f"s-{i:03d}", f"app{i}:latest")
        page1 = history.list_scan_reports(limit=2, offset=0)
        page2 = history.list_scan_reports(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["scan_id"] != page2[0]["scan_id"]


class TestDeleteScanReport:
    def test_delete_existing(self, history):
        history.save_scan_report("s-001", "app:latest")
        assert history.delete_scan_report("s-001") is True
        assert history.get_scan_report("s-001") is None

    def test_delete_nonexistent_returns_false(self, history):
        assert history.delete_scan_report("no-exist") is False
