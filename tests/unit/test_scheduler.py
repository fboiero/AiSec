"""Tests for the scan scheduler module."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


def _scheduler_available() -> bool:
    try:
        from aisec.core.scheduler import is_available
        return is_available()
    except Exception:
        return False


class TestSchedulerAvailability:
    """Test scheduler availability detection."""

    def test_is_available(self):
        from aisec.core.scheduler import is_available
        assert isinstance(is_available(), bool)

    def test_parse_cron_aliases(self):
        from aisec.core.scheduler import parse_cron
        assert parse_cron("@hourly") == "0 * * * *"
        assert parse_cron("@daily") == "0 2 * * *"
        assert parse_cron("@weekly") == "0 2 * * 0"
        assert parse_cron("@monthly") == "0 2 1 * *"

    def test_parse_cron_passthrough(self):
        from aisec.core.scheduler import parse_cron
        assert parse_cron("30 4 * * 1-5") == "30 4 * * 1-5"


class TestScheduleEntry:
    """Test ScheduleEntry dataclass."""

    def test_to_dict(self):
        from aisec.core.scheduler import ScheduleEntry
        entry = ScheduleEntry(
            schedule_id="abc123",
            image="myapp:latest",
            cron="0 2 * * *",
            created_at="2026-01-01T00:00:00Z",
        )
        d = entry.to_dict()
        assert d["schedule_id"] == "abc123"
        assert d["image"] == "myapp:latest"
        assert d["cron"] == "0 2 * * *"
        assert d["agents"] == ["all"]
        assert d["language"] == "en"
        assert d["run_count"] == 0
        assert d["last_run"] is None


@pytest.mark.skipif(
    not _scheduler_available(),
    reason="apscheduler not installed",
)
class TestScanScheduler:
    """Test the ScanScheduler class."""

    def test_add_schedule(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        entry = scheduler.add_schedule("myapp:latest", "0 2 * * *")
        assert entry.image == "myapp:latest"
        assert entry.cron == "0 2 * * *"
        assert entry.schedule_id
        scheduler.stop()

    def test_add_schedule_with_alias(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        entry = scheduler.add_schedule("myapp:latest", "@daily")
        assert entry.cron == "0 2 * * *"
        scheduler.stop()

    def test_list_schedules(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        scheduler.add_schedule("img1:latest", "0 * * * *")
        scheduler.add_schedule("img2:latest", "0 2 * * *")
        schedules = scheduler.list_schedules()
        assert len(schedules) == 2
        scheduler.stop()

    def test_remove_schedule(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        entry = scheduler.add_schedule("myapp:latest", "0 2 * * *")
        assert scheduler.remove_schedule(entry.schedule_id) is True
        assert scheduler.list_schedules() == []
        scheduler.stop()

    def test_remove_nonexistent(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        assert scheduler.remove_schedule("nonexistent") is False
        scheduler.stop()

    def test_get_schedule(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        entry = scheduler.add_schedule("myapp:latest", "0 2 * * *")
        found = scheduler.get_schedule(entry.schedule_id)
        assert found is not None
        assert found.image == "myapp:latest"
        assert scheduler.get_schedule("nonexistent") is None
        scheduler.stop()

    def test_start_stop(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        scheduler.start()
        scheduler.stop()

    def test_callback_invoked(self):
        from aisec.core.scheduler import ScanScheduler
        callback = MagicMock()
        scheduler = ScanScheduler(scan_callback=callback)
        entry = scheduler.add_schedule("myapp:latest", "0 2 * * *", agents=["network"])
        # Manually trigger the internal execute
        scheduler._execute_schedule(entry.schedule_id)
        callback.assert_called_once_with(
            image="myapp:latest", agents=["network"], language="en"
        )
        assert entry.run_count == 1
        assert entry.last_run is not None
        scheduler.stop()

    def test_custom_agents_and_language(self):
        from aisec.core.scheduler import ScanScheduler
        scheduler = ScanScheduler()
        entry = scheduler.add_schedule(
            "myapp:latest", "0 2 * * *",
            agents=["network", "prompt_security"],
            language="es",
        )
        assert entry.agents == ["network", "prompt_security"]
        assert entry.language == "es"
        scheduler.stop()
