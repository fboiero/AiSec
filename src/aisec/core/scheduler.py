"""Scan scheduler for recurring security scans.

Uses APScheduler to run scans on cron schedules. Gracefully degrades
when ``apscheduler`` is not installed.

Install: ``pip install aisec[scheduler]``
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    _HAS_APSCHEDULER = True
except ImportError:
    _HAS_APSCHEDULER = False

# Shorthand aliases for common schedules
_ALIASES: dict[str, str] = {
    "@hourly": "0 * * * *",
    "@daily": "0 2 * * *",
    "@weekly": "0 2 * * 0",
    "@monthly": "0 2 1 * *",
}


@dataclass
class ScheduleEntry:
    """A scheduled scan definition."""

    schedule_id: str
    image: str
    cron: str
    agents: list[str] = field(default_factory=lambda: ["all"])
    language: str = "en"
    created_at: str = ""
    last_run: str | None = None
    run_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "image": self.image,
            "cron": self.cron,
            "agents": self.agents,
            "language": self.language,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "run_count": self.run_count,
        }


class ScanScheduler:
    """Manages recurring scan schedules using APScheduler."""

    def __init__(self, scan_callback: Callable[..., Any] | None = None) -> None:
        """
        Args:
            scan_callback: Function called when a scheduled scan fires.
                Signature: ``callback(image, agents, language) -> None``
        """
        if not _HAS_APSCHEDULER:
            raise RuntimeError(
                "apscheduler is required for scan scheduling. "
                "Install with: pip install aisec[scheduler]"
            )
        self._scheduler = BackgroundScheduler()
        self._schedules: dict[str, ScheduleEntry] = {}
        self._scan_callback = scan_callback

    def add_schedule(
        self,
        image: str,
        cron: str,
        agents: list[str] | None = None,
        language: str = "en",
    ) -> ScheduleEntry:
        """Add a new recurring scan schedule.

        Args:
            image: Docker image to scan.
            cron: Cron expression (5-field) or alias (@hourly, @daily, etc.)
            agents: Agents to run (default: all).
            language: Report language.

        Returns:
            The created ScheduleEntry.
        """
        cron_expr = _ALIASES.get(cron, cron)
        schedule_id = str(uuid.uuid4())[:8]
        agents = agents or ["all"]

        entry = ScheduleEntry(
            schedule_id=schedule_id,
            image=image,
            cron=cron_expr,
            agents=agents,
            language=language,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        trigger = CronTrigger.from_crontab(cron_expr)
        self._scheduler.add_job(
            self._execute_schedule,
            trigger=trigger,
            id=schedule_id,
            args=[schedule_id],
            name=f"scan-{image}-{schedule_id}",
        )

        self._schedules[schedule_id] = entry
        logger.info(
            "Schedule added: %s image=%s cron='%s'", schedule_id, image, cron_expr
        )
        return entry

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule by ID. Returns True if removed."""
        if schedule_id not in self._schedules:
            return False
        try:
            self._scheduler.remove_job(schedule_id)
        except Exception:
            pass  # Job may not exist in APScheduler yet
        del self._schedules[schedule_id]
        logger.info("Schedule removed: %s", schedule_id)
        return True

    def list_schedules(self) -> list[dict[str, Any]]:
        """Return all schedules as dicts."""
        return [entry.to_dict() for entry in self._schedules.values()]

    def get_schedule(self, schedule_id: str) -> ScheduleEntry | None:
        """Get a single schedule by ID."""
        return self._schedules.get(schedule_id)

    def start(self) -> None:
        """Start the scheduler."""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("Scan scheduler started with %d schedules", len(self._schedules))

    def stop(self) -> None:
        """Stop the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("Scan scheduler stopped")

    def _execute_schedule(self, schedule_id: str) -> None:
        """Internal callback when a schedule fires."""
        entry = self._schedules.get(schedule_id)
        if not entry:
            return

        entry.last_run = datetime.now(timezone.utc).isoformat()
        entry.run_count += 1
        logger.info(
            "Scheduled scan firing: %s image=%s (run #%d)",
            schedule_id,
            entry.image,
            entry.run_count,
        )

        if self._scan_callback:
            try:
                self._scan_callback(
                    image=entry.image,
                    agents=entry.agents,
                    language=entry.language,
                )
            except Exception:
                logger.exception("Scheduled scan failed: %s", schedule_id)


def is_available() -> bool:
    """Return True if apscheduler is installed."""
    return _HAS_APSCHEDULER


def parse_cron(cron: str) -> str:
    """Resolve aliases and validate cron expression."""
    return _ALIASES.get(cron, cron)
