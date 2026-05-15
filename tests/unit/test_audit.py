"""Tests for AuditLogger (Phase 3)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class TestAuditLogger(unittest.TestCase):
    """Verify AuditLogger CRUD operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test_audit.db"

    def _make_logger(self):
        from aisec.core.audit import AuditLogger
        return AuditLogger(db_path=self.db_path)

    def test_log_event_returns_event_id(self):
        audit = self._make_logger()
        event_id = audit.log_event(
            action="scan.created",
            resource_type="scan",
            resource_id="abc123",
        )
        self.assertIsInstance(event_id, str)
        self.assertTrue(len(event_id) > 0)
        audit.close()

    def test_list_events_returns_logged_events(self):
        audit = self._make_logger()
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s1")
        audit.log_event(action="webhook.created", resource_type="webhook", resource_id="w1")

        events = audit.list_events()
        self.assertEqual(len(events), 2)
        audit.close()

    def test_list_events_filter_by_action(self):
        audit = self._make_logger()
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s1")
        audit.log_event(action="webhook.created", resource_type="webhook", resource_id="w1")

        events = audit.list_events(action="scan.created")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["action"], "scan.created")
        audit.close()

    def test_list_events_filter_by_resource_type(self):
        audit = self._make_logger()
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s1")
        audit.log_event(action="webhook.created", resource_type="webhook", resource_id="w1")

        events = audit.list_events(resource_type="webhook")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["resource_type"], "webhook")
        audit.close()

    def test_count_events(self):
        audit = self._make_logger()
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s1")
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s2")
        audit.log_event(action="webhook.deleted", resource_type="webhook", resource_id="w1")

        total = audit.count_events()
        self.assertEqual(total, 3)

        scan_count = audit.count_events(action="scan.created")
        self.assertEqual(scan_count, 2)
        audit.close()

    def test_get_events_for_resource(self):
        audit = self._make_logger()
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s1")
        audit.log_event(action="scan.deleted", resource_type="scan", resource_id="s1")
        audit.log_event(action="scan.created", resource_type="scan", resource_id="s2")

        events = audit.get_events_for_resource("scan", "s1")
        self.assertEqual(len(events), 2)
        audit.close()

    def test_event_contains_all_fields(self):
        audit = self._make_logger()
        audit.log_event(
            action="scan.created",
            resource_type="scan",
            resource_id="s1",
            actor="api_key",
            details="image=myapp:latest",
            request_id="req123",
            ip_address="192.168.1.1",
        )

        events = audit.list_events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["action"], "scan.created")
        self.assertEqual(ev["resource_type"], "scan")
        self.assertEqual(ev["resource_id"], "s1")
        self.assertEqual(ev["actor"], "api_key")
        self.assertEqual(ev["details"], "image=myapp:latest")
        self.assertEqual(ev["request_id"], "req123")
        self.assertEqual(ev["ip_address"], "192.168.1.1")
        self.assertIn("timestamp", ev)
        self.assertIn("event_id", ev)
        audit.close()

    def test_schema_created_in_history_db(self):
        """Verify audit_events table is created as part of history schema."""
        from aisec.core.history import ScanHistory
        db = Path(self.tmpdir) / "history_with_audit.db"
        history = ScanHistory(db_path=db)
        # The schema should now include audit_events
        conn = history._get_conn()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'"
        )
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        history.close()


if __name__ == "__main__":
    unittest.main()
