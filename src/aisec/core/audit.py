"""Audit logging for the AiSec REST API.

Provides an ``AuditLogger`` class that records security-relevant events
(scan creation, deletion, webhook management, etc.) to a SQLite table
for compliance and forensic tracing.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".aisec" / "history.db"

_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    actor TEXT,
    details TEXT,
    request_id TEXT,
    ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id);
"""


class AuditLogger:
    """SQLite-backed audit event logger."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._ensure_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _ensure_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_AUDIT_SCHEMA)
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def log_event(
        self,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        actor: str | None = None,
        details: str | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
    ) -> str:
        """Record an audit event.

        Args:
            action: Event action (e.g. "scan.created", "webhook.deleted").
            resource_type: Type of resource (e.g. "scan", "webhook").
            resource_id: Optional resource identifier.
            actor: Who performed the action (API key user, IP, etc.).
            details: Free-text details about the event.
            request_id: Correlation ID from the HTTP request.
            ip_address: Client IP address.

        Returns:
            The event_id.
        """
        conn = self._get_conn()
        event_id = str(uuid4())[:12]
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO audit_events
            (event_id, timestamp, action, resource_type, resource_id,
             actor, details, request_id, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, now, action, resource_type, resource_id,
             actor, details, request_id, ip_address),
        )
        conn.commit()
        logger.debug("Audit event: %s %s/%s", action, resource_type, resource_id)
        return event_id

    def list_events(
        self,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List audit events with optional filtering."""
        conn = self._get_conn()
        clauses: list[str] = []
        params: list[Any] = []

        if action:
            clauses.append("action = ?")
            params.append(action)
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if resource_id:
            clauses.append("resource_id = ?")
            params.append(resource_id)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([limit, offset])

        rows = conn.execute(
            f"SELECT * FROM audit_events{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def count_events(
        self,
        action: str | None = None,
        resource_type: str | None = None,
    ) -> int:
        """Count audit events with optional filtering."""
        conn = self._get_conn()
        clauses: list[str] = []
        params: list[Any] = []

        if action:
            clauses.append("action = ?")
            params.append(action)
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        row = conn.execute(
            f"SELECT COUNT(*) FROM audit_events{where}",
            params,
        ).fetchone()
        return row[0]

    def get_events_for_resource(
        self,
        resource_type: str,
        resource_id: str,
    ) -> list[dict[str, Any]]:
        """Get all audit events for a specific resource."""
        return self.list_events(
            resource_type=resource_type,
            resource_id=resource_id,
            limit=1000,
        )
