"""Scan history storage and trending with SQLite.

Provides persistent storage of scan results for tracking security posture
over time, generating trend reports, and managing baselines.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".aisec" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_image TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_seconds REAL,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    overall_risk_level TEXT,
    ai_risk_score REAL,
    compliance_score REAL,
    aisec_version TEXT,
    language TEXT DEFAULT 'en',
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    agent TEXT,
    owasp_llm TEXT,
    owasp_agentic TEXT,
    nist_ai_rmf TEXT,
    cvss_score REAL,
    ai_risk_score REAL,
    status TEXT DEFAULT 'open',
    UNIQUE(scan_id, finding_id)
);

CREATE TABLE IF NOT EXISTS baselines (
    baseline_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_image TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    created_at TEXT NOT NULL,
    description TEXT DEFAULT '',
    UNIQUE(name, target_image)
);

CREATE TABLE IF NOT EXISTS scan_policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_reports (
    scan_id TEXT PRIMARY KEY,
    target_image TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    report_json TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error_message TEXT,
    finding_count INTEGER DEFAULT 0,
    image TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    secret TEXT DEFAULT '',
    events TEXT NOT NULL DEFAULT '["scan.completed","scan.failed"]',
    created_at TEXT NOT NULL,
    active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_image);
CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_baselines_target ON baselines(target_image);
CREATE INDEX IF NOT EXISTS idx_scan_reports_status ON scan_reports(status);
CREATE INDEX IF NOT EXISTS idx_scan_reports_target ON scan_reports(target_image);
CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active);
"""


class _Encoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


class ScanHistory:
    """SQLite-backed scan history for tracking security posture over time."""

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
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _ensure_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def save_scan(self, report: Any) -> str:
        """Save a ScanReport to the history database.

        Args:
            report: A ScanReport dataclass instance.

        Returns:
            The scan_id as a string.
        """
        conn = self._get_conn()
        scan_id = str(report.scan_id)
        es = report.executive_summary
        ro = report.risk_overview

        conn.execute(
            """INSERT OR REPLACE INTO scans
            (scan_id, report_id, target_name, target_image, started_at,
             completed_at, duration_seconds, total_findings, critical_count,
             high_count, medium_count, low_count, info_count,
             overall_risk_level, ai_risk_score, compliance_score,
             aisec_version, language, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                str(report.report_id),
                report.target_name,
                report.target_image,
                report.generated_at.isoformat() if report.generated_at else datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
                report.scan_duration_seconds,
                es.total_findings,
                es.critical_count,
                es.high_count,
                es.medium_count,
                es.low_count,
                es.info_count,
                es.overall_risk_level.value if hasattr(es.overall_risk_level, "value") else str(es.overall_risk_level),
                ro.ai_risk_score,
                ro.compliance_score,
                report.aisec_version,
                report.language,
                json.dumps({"top_risks": es.top_risks}, cls=_Encoder),
            ),
        )

        # Store individual findings
        for finding in report.all_findings:
            conn.execute(
                """INSERT OR IGNORE INTO findings
                (scan_id, finding_id, title, severity, agent,
                 owasp_llm, owasp_agentic, nist_ai_rmf,
                 cvss_score, ai_risk_score, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    str(finding.id),
                    finding.title,
                    finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    finding.agent,
                    json.dumps(finding.owasp_llm),
                    json.dumps(finding.owasp_agentic),
                    json.dumps(finding.nist_ai_rmf),
                    finding.cvss_score,
                    finding.ai_risk_score,
                    finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                ),
            )

        conn.commit()
        logger.info("Saved scan %s to history (%d findings)", scan_id, es.total_findings)
        return scan_id

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan summary by ID."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(
        self,
        target_image: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List scan summaries, optionally filtered by target image."""
        conn = self._get_conn()
        if target_image:
            rows = conn.execute(
                "SELECT * FROM scans WHERE target_image = ? ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (target_image, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Retrieve all findings for a scan."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_trend(
        self,
        target_image: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get finding count trends for a target image.

        Returns a list of scan summaries ordered chronologically,
        suitable for plotting trend charts.
        """
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT scan_id, started_at, total_findings,
                      critical_count, high_count, medium_count,
                      low_count, info_count, ai_risk_score,
                      compliance_score, overall_risk_level
            FROM scans
            WHERE target_image = ?
            ORDER BY started_at ASC
            LIMIT ?""",
            (target_image, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_findings(
        self,
        current_scan_id: str,
        previous_scan_id: str,
    ) -> list[dict[str, Any]]:
        """Find findings in the current scan that weren't in the previous scan.

        Uses title matching for comparison (not UUID, since those change).
        """
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT f.*
            FROM findings f
            WHERE f.scan_id = ?
            AND f.title NOT IN (
                SELECT title FROM findings WHERE scan_id = ?
            )
            ORDER BY f.severity""",
            (current_scan_id, previous_scan_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_resolved_findings(
        self,
        current_scan_id: str,
        previous_scan_id: str,
    ) -> list[dict[str, Any]]:
        """Find findings from the previous scan that are no longer present."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT f.*
            FROM findings f
            WHERE f.scan_id = ?
            AND f.title NOT IN (
                SELECT title FROM findings WHERE scan_id = ?
            )
            ORDER BY f.severity""",
            (previous_scan_id, current_scan_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def severity_distribution(self) -> dict[str, int]:
        """Aggregate severity counts across all findings."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def search_findings(
        self,
        severity: str | None = None,
        agent: str | None = None,
        framework: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Filtered/paginated cross-scan finding search."""
        conn = self._get_conn()
        clauses: list[str] = []
        params: list[Any] = []

        if severity:
            clauses.append("f.severity = ?")
            params.append(severity)
        if agent:
            clauses.append("f.agent = ?")
            params.append(agent)
        if framework:
            clauses.append(
                "(f.owasp_llm LIKE ? OR f.owasp_agentic LIKE ? OR f.nist_ai_rmf LIKE ?)"
            )
            pattern = f"%{framework}%"
            params.extend([pattern, pattern, pattern])
        if status:
            clauses.append("f.status = ?")
            params.append(status)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([limit, offset])

        rows = conn.execute(
            f"SELECT f.*, s.target_image, s.started_at AS scan_date "
            f"FROM findings f JOIN scans s ON f.scan_id = s.scan_id"
            f"{where} ORDER BY s.started_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def global_trend(self, limit: int = 30) -> list[dict[str, Any]]:
        """Aggregate trend across all targets by date."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT DATE(started_at) as scan_date,
                      COUNT(*) as scan_count,
                      SUM(total_findings) as total_findings,
                      SUM(critical_count) as critical_count,
                      SUM(high_count) as high_count,
                      SUM(medium_count) as medium_count,
                      SUM(low_count) as low_count,
                      SUM(info_count) as info_count,
                      AVG(ai_risk_score) as avg_risk_score
               FROM scans
               GROUP BY DATE(started_at)
               ORDER BY scan_date DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def distinct_targets(self) -> list[str]:
        """Return unique target images for dropdown selectors."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT DISTINCT target_image FROM scans ORDER BY target_image"
        ).fetchall()
        return [r["target_image"] for r in rows]

    def count_scans(self, target_image: str | None = None) -> int:
        """Total scan count, optionally filtered by target image."""
        conn = self._get_conn()
        if target_image:
            row = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE target_image = ?",
                (target_image,),
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        return row[0]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings from history."""
        conn = self._get_conn()
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        result = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return result.rowcount > 0

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics from the history database."""
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        targets = conn.execute("SELECT COUNT(DISTINCT target_image) FROM scans").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        baselines = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
        policies = conn.execute("SELECT COUNT(*) FROM scan_policies").fetchone()[0]
        scan_reports = conn.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
        webhooks_count = conn.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0]
        return {
            "total_scans": total,
            "unique_targets": targets,
            "total_findings": findings,
            "baselines": baselines,
            "scan_policies": policies,
            "scan_reports": scan_reports,
            "webhooks": webhooks_count,
            "db_path": str(self.db_path),
        }

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    def save_baseline(
        self,
        name: str,
        target_image: str,
        scan_id: str,
        description: str = "",
    ) -> str:
        """Save a scan as a named baseline for future comparison.

        Args:
            name: Baseline name (e.g. "release-v1.0", "pre-deploy").
            target_image: The Docker image this baseline applies to.
            scan_id: The scan to use as the baseline.
            description: Optional description.

        Returns:
            The baseline_id.
        """
        conn = self._get_conn()
        baseline_id = str(uuid4())[:12]
        conn.execute(
            """INSERT OR REPLACE INTO baselines
            (baseline_id, name, target_image, scan_id, created_at, description)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                baseline_id,
                name,
                target_image,
                scan_id,
                datetime.now(timezone.utc).isoformat(),
                description,
            ),
        )
        conn.commit()
        logger.info("Saved baseline '%s' for %s (scan %s)", name, target_image, scan_id)
        return baseline_id

    def get_baseline(self, name: str, target_image: str) -> dict[str, Any] | None:
        """Retrieve a baseline by name and target image."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM baselines WHERE name = ? AND target_image = ?",
            (name, target_image),
        ).fetchone()
        return dict(row) if row else None

    def list_baselines(self, target_image: str | None = None) -> list[dict[str, Any]]:
        """List all baselines, optionally filtered by target image."""
        conn = self._get_conn()
        if target_image:
            rows = conn.execute(
                "SELECT * FROM baselines WHERE target_image = ? ORDER BY created_at DESC",
                (target_image,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM baselines ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def compare_to_baseline(
        self,
        current_scan_id: str,
        baseline_name: str,
        target_image: str,
    ) -> dict[str, Any]:
        """Compare a scan against a named baseline.

        Returns a dict with new findings, resolved findings, and summary.
        """
        baseline = self.get_baseline(baseline_name, target_image)
        if not baseline:
            return {"error": f"Baseline '{baseline_name}' not found for {target_image}"}

        baseline_scan_id = baseline["scan_id"]
        new = self.get_new_findings(current_scan_id, baseline_scan_id)
        resolved = self.get_resolved_findings(current_scan_id, baseline_scan_id)

        current_scan = self.get_scan(current_scan_id)
        baseline_scan = self.get_scan(baseline_scan_id)

        return {
            "baseline_name": baseline_name,
            "baseline_scan_id": baseline_scan_id,
            "current_scan_id": current_scan_id,
            "new_findings": new,
            "resolved_findings": resolved,
            "new_count": len(new),
            "resolved_count": len(resolved),
            "baseline_total": baseline_scan["total_findings"] if baseline_scan else 0,
            "current_total": current_scan["total_findings"] if current_scan else 0,
            "regression": len(new) > 0,
        }

    def delete_baseline(self, name: str, target_image: str) -> bool:
        """Delete a named baseline."""
        conn = self._get_conn()
        result = conn.execute(
            "DELETE FROM baselines WHERE name = ? AND target_image = ?",
            (name, target_image),
        )
        conn.commit()
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Shared scan policies
    # ------------------------------------------------------------------

    def save_policy(
        self,
        name: str,
        config: dict[str, Any],
        description: str = "",
    ) -> str:
        """Save a named scan policy (shared config preset).

        Args:
            name: Policy name (e.g. "production", "quick-check").
            config: AiSecConfig fields as a dict.
            description: Optional description.

        Returns:
            The policy_id.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        policy_id = str(uuid4())[:12]
        conn.execute(
            """INSERT OR REPLACE INTO scan_policies
            (policy_id, name, config_json, created_at, updated_at, description)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (policy_id, name, json.dumps(config, cls=_Encoder), now, now, description),
        )
        conn.commit()
        logger.info("Saved scan policy '%s'", name)
        return policy_id

    def get_policy(self, name: str) -> dict[str, Any] | None:
        """Retrieve a scan policy by name."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scan_policies WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["config"] = json.loads(result.pop("config_json"))
        return result

    def list_policies(self) -> list[dict[str, Any]]:
        """List all scan policies."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT policy_id, name, description, created_at, updated_at FROM scan_policies ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_policy(self, name: str) -> bool:
        """Delete a scan policy by name."""
        conn = self._get_conn()
        result = conn.execute("DELETE FROM scan_policies WHERE name = ?", (name,))
        conn.commit()
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Scan report persistence (API server state)
    # ------------------------------------------------------------------

    def save_scan_report(
        self,
        scan_id: str,
        target_image: str,
        status: str = "pending",
        image: str = "",
    ) -> str:
        """Create a scan report entry (initially pending)."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT OR REPLACE INTO scan_reports
            (scan_id, target_image, status, created_at, image)
            VALUES (?, ?, ?, ?, ?)""",
            (scan_id, target_image, status, now, image),
        )
        conn.commit()
        return scan_id

    def update_scan_report(
        self,
        scan_id: str,
        status: str | None = None,
        report_json: str | None = None,
        error_message: str | None = None,
        finding_count: int | None = None,
    ) -> bool:
        """Update fields of an existing scan report."""
        conn = self._get_conn()
        updates: list[str] = []
        params: list[Any] = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if report_json is not None:
            updates.append("report_json = ?")
            params.append(report_json)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if finding_count is not None:
            updates.append("finding_count = ?")
            params.append(finding_count)
        if status in ("completed", "failed"):
            updates.append("completed_at = ?")
            params.append(datetime.now(timezone.utc).isoformat())
        if not updates:
            return False
        params.append(scan_id)
        result = conn.execute(
            f"UPDATE scan_reports SET {', '.join(updates)} WHERE scan_id = ?",
            params,
        )
        conn.commit()
        return result.rowcount > 0

    def get_scan_report(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan report by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scan_reports WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        if result.get("report_json"):
            result["report"] = json.loads(result["report_json"])
        else:
            result["report"] = None
        return result

    def list_scan_reports(
        self, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List scan reports (without full report JSON for performance)."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT scan_id, target_image, status, image,
                      created_at, completed_at, finding_count, error_message
            FROM scan_reports ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_scan_report(self, scan_id: str) -> bool:
        """Delete a scan report."""
        conn = self._get_conn()
        result = conn.execute(
            "DELETE FROM scan_reports WHERE scan_id = ?", (scan_id,)
        )
        conn.commit()
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Webhook persistence
    # ------------------------------------------------------------------

    def save_webhook(
        self,
        webhook_id: str,
        url: str,
        secret: str = "",
        events: list[str] | None = None,
    ) -> str:
        """Save a webhook registration."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        events_json = json.dumps(events or ["scan.completed", "scan.failed"])
        conn.execute(
            """INSERT OR REPLACE INTO webhooks
            (webhook_id, url, secret, events, created_at, active)
            VALUES (?, ?, ?, ?, ?, 1)""",
            (webhook_id, url, secret, events_json, now),
        )
        conn.commit()
        return webhook_id

    def list_webhooks(self, active_only: bool = True) -> list[dict[str, Any]]:
        """List registered webhooks."""
        conn = self._get_conn()
        if active_only:
            rows = conn.execute(
                "SELECT * FROM webhooks WHERE active = 1 ORDER BY created_at"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM webhooks ORDER BY created_at"
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["events"] = json.loads(d.get("events", "[]"))
            results.append(d)
        return results

    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook."""
        conn = self._get_conn()
        result = conn.execute(
            "DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,)
        )
        conn.commit()
        return result.rowcount > 0

    def get_webhook(self, webhook_id: str) -> dict[str, Any] | None:
        """Retrieve a single webhook by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM webhooks WHERE webhook_id = ?", (webhook_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["events"] = json.loads(d.get("events", "[]"))
        return d
