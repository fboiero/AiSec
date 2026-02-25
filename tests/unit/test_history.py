"""Tests for the scan history SQLite storage."""

import tempfile
from pathlib import Path

from aisec.core.history import ScanHistory


# ---------------------------------------------------------------------------
# ScanHistory creation
# ---------------------------------------------------------------------------


class TestScanHistoryCreation:
    def test_creates_db_file(self, tmp_path: Path):
        db_path = tmp_path / "test_history.db"
        history = ScanHistory(db_path=db_path)
        try:
            assert db_path.exists()
        finally:
            history.close()

    def test_creates_parent_directories(self, tmp_path: Path):
        db_path = tmp_path / "nested" / "deep" / "history.db"
        history = ScanHistory(db_path=db_path)
        try:
            assert db_path.exists()
        finally:
            history.close()

    def test_accepts_string_path(self, tmp_path: Path):
        db_path = str(tmp_path / "string_path.db")
        history = ScanHistory(db_path=db_path)
        try:
            assert Path(db_path).exists()
        finally:
            history.close()

    def test_with_tempfile(self):
        """ScanHistory works with a tempfile-based path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "temp_history.db"
            history = ScanHistory(db_path=db_path)
            try:
                assert db_path.exists()
            finally:
                history.close()


# ---------------------------------------------------------------------------
# stats()
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_on_empty_db(self, tmp_path: Path):
        db_path = tmp_path / "empty.db"
        history = ScanHistory(db_path=db_path)
        try:
            result = history.stats()
            assert result["total_scans"] == 0
            assert result["unique_targets"] == 0
            assert result["total_findings"] == 0
            assert "db_path" in result
        finally:
            history.close()

    def test_stats_returns_correct_keys(self, tmp_path: Path):
        db_path = tmp_path / "keys.db"
        history = ScanHistory(db_path=db_path)
        try:
            result = history.stats()
            expected_keys = {"total_scans", "unique_targets", "total_findings", "baselines", "scan_policies", "scan_reports", "webhooks", "db_path"}
            assert set(result.keys()) == expected_keys
        finally:
            history.close()

    def test_stats_db_path_matches(self, tmp_path: Path):
        db_path = tmp_path / "path_check.db"
        history = ScanHistory(db_path=db_path)
        try:
            result = history.stats()
            assert result["db_path"] == str(db_path)
        finally:
            history.close()


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------


class TestSchemaCreation:
    def test_scans_table_exists(self, tmp_path: Path):
        db_path = tmp_path / "schema.db"
        history = ScanHistory(db_path=db_path)
        try:
            conn = history._get_conn()
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
            )
            row = cursor.fetchone()
            assert row is not None
            assert row["name"] == "scans"
        finally:
            history.close()

    def test_findings_table_exists(self, tmp_path: Path):
        db_path = tmp_path / "schema.db"
        history = ScanHistory(db_path=db_path)
        try:
            conn = history._get_conn()
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
            )
            row = cursor.fetchone()
            assert row is not None
            assert row["name"] == "findings"
        finally:
            history.close()

    def test_indexes_exist(self, tmp_path: Path):
        db_path = tmp_path / "schema.db"
        history = ScanHistory(db_path=db_path)
        try:
            conn = history._get_conn()
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
            index_names = {row["name"] for row in cursor.fetchall()}
            assert "idx_scans_target" in index_names
            assert "idx_scans_date" in index_names
            assert "idx_findings_scan" in index_names
            assert "idx_findings_severity" in index_names
        finally:
            history.close()

    def test_schema_idempotent(self, tmp_path: Path):
        """Calling _ensure_schema twice does not raise."""
        db_path = tmp_path / "idem.db"
        history = ScanHistory(db_path=db_path)
        try:
            # Second call should not fail (CREATE TABLE IF NOT EXISTS)
            history._ensure_schema()
            result = history.stats()
            assert result["total_scans"] == 0
        finally:
            history.close()


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------


class TestListScans:
    def test_empty_db_returns_empty_list(self, tmp_path: Path):
        db_path = tmp_path / "list.db"
        history = ScanHistory(db_path=db_path)
        try:
            scans = history.list_scans()
            assert scans == []
        finally:
            history.close()

    def test_empty_db_with_target_filter(self, tmp_path: Path):
        db_path = tmp_path / "list_filter.db"
        history = ScanHistory(db_path=db_path)
        try:
            scans = history.list_scans(target_image="nonexistent:latest")
            assert scans == []
        finally:
            history.close()

    def test_empty_db_with_limit_and_offset(self, tmp_path: Path):
        db_path = tmp_path / "list_paged.db"
        history = ScanHistory(db_path=db_path)
        try:
            scans = history.list_scans(limit=10, offset=5)
            assert scans == []
        finally:
            history.close()


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_without_error(self, tmp_path: Path):
        db_path = tmp_path / "close.db"
        history = ScanHistory(db_path=db_path)
        # Should not raise
        history.close()

    def test_close_sets_conn_to_none(self, tmp_path: Path):
        db_path = tmp_path / "close_none.db"
        history = ScanHistory(db_path=db_path)
        history.close()
        assert history._conn is None

    def test_double_close_without_error(self, tmp_path: Path):
        db_path = tmp_path / "double_close.db"
        history = ScanHistory(db_path=db_path)
        history.close()
        # Second close should not raise
        history.close()
        assert history._conn is None

    def test_operations_after_close_reconnect(self, tmp_path: Path):
        """After close, calling stats() should reconnect automatically."""
        db_path = tmp_path / "reconnect.db"
        history = ScanHistory(db_path=db_path)
        history.close()
        # _get_conn will create a new connection
        result = history.stats()
        assert result["total_scans"] == 0
        history.close()
