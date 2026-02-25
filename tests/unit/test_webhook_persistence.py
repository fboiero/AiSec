"""Tests for webhook persistence in ScanHistory."""

import pytest

from aisec.core.history import ScanHistory


@pytest.fixture
def history(tmp_path):
    db = ScanHistory(db_path=tmp_path / "test.db")
    yield db
    db.close()


class TestWebhookTable:
    def test_table_exists(self, history):
        conn = history._get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='webhooks'"
        ).fetchone()
        assert row is not None

    def test_index_exists(self, history):
        conn = history._get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_webhooks_active'"
        ).fetchone()
        assert row is not None


class TestSaveWebhook:
    def test_save_basic(self, history):
        wid = history.save_webhook("wh-001", "https://example.com/hook")
        assert wid == "wh-001"
        wh = history.get_webhook("wh-001")
        assert wh is not None
        assert wh["url"] == "https://example.com/hook"
        assert wh["events"] == ["scan.completed", "scan.failed"]

    def test_save_with_secret_and_events(self, history):
        history.save_webhook(
            "wh-002",
            "https://example.com/hook2",
            secret="s3cret",
            events=["scan.completed"],
        )
        wh = history.get_webhook("wh-002")
        assert wh["secret"] == "s3cret"
        assert wh["events"] == ["scan.completed"]


class TestListWebhooks:
    def test_list_empty(self, history):
        assert history.list_webhooks() == []

    def test_list_active_only(self, history):
        history.save_webhook("wh-001", "https://a.com/hook")
        history.save_webhook("wh-002", "https://b.com/hook")
        # Deactivate one directly
        conn = history._get_conn()
        conn.execute("UPDATE webhooks SET active = 0 WHERE webhook_id = 'wh-002'")
        conn.commit()
        active = history.list_webhooks(active_only=True)
        assert len(active) == 1
        assert active[0]["webhook_id"] == "wh-001"

    def test_list_all(self, history):
        history.save_webhook("wh-001", "https://a.com/hook")
        history.save_webhook("wh-002", "https://b.com/hook")
        conn = history._get_conn()
        conn.execute("UPDATE webhooks SET active = 0 WHERE webhook_id = 'wh-002'")
        conn.commit()
        all_wh = history.list_webhooks(active_only=False)
        assert len(all_wh) == 2


class TestDeleteWebhook:
    def test_delete_existing(self, history):
        history.save_webhook("wh-001", "https://a.com/hook")
        assert history.delete_webhook("wh-001") is True
        assert history.get_webhook("wh-001") is None

    def test_delete_nonexistent(self, history):
        assert history.delete_webhook("no-exist") is False


class TestGetWebhook:
    def test_get_existing(self, history):
        history.save_webhook("wh-001", "https://a.com/hook")
        wh = history.get_webhook("wh-001")
        assert wh is not None
        assert wh["webhook_id"] == "wh-001"

    def test_get_events_parsed_as_list(self, history):
        history.save_webhook("wh-001", "https://a.com/hook", events=["scan.failed"])
        wh = history.get_webhook("wh-001")
        assert isinstance(wh["events"], list)
        assert wh["events"] == ["scan.failed"]

    def test_get_nonexistent(self, history):
        assert history.get_webhook("no-exist") is None
