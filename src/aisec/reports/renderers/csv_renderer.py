"""CSV report renderer.

Flattens a :class:`~aisec.core.models.ScanReport` into tabular rows
suitable for spreadsheet analysis and CI/CD integration.
"""

from __future__ import annotations

import csv
from datetime import datetime
from enum import Enum
from pathlib import Path
from uuid import UUID

from aisec.core.models import ScanReport


def _flatten_finding(finding: object, scan_target: str, scan_date: str) -> dict:
    """Convert a Finding dataclass to a flat dict for CSV output."""
    sev = getattr(finding, "severity", "")
    if isinstance(sev, Enum):
        sev = sev.value
    status = getattr(finding, "status", "")
    if isinstance(status, Enum):
        status = status.value
    fid = getattr(finding, "id", "")
    if isinstance(fid, UUID):
        fid = str(fid)

    return {
        "target": scan_target,
        "scan_date": scan_date,
        "finding_id": fid,
        "title": getattr(finding, "title", ""),
        "severity": sev,
        "status": status,
        "agent": getattr(finding, "agent", ""),
        "description": getattr(finding, "description", ""),
        "remediation": getattr(finding, "remediation", ""),
        "cvss_score": getattr(finding, "cvss_score", ""),
        "ai_risk_score": getattr(finding, "ai_risk_score", ""),
        "owasp_llm": ",".join(getattr(finding, "owasp_llm", [])),
        "owasp_agentic": ",".join(getattr(finding, "owasp_agentic", [])),
        "nist_ai_rmf": ",".join(getattr(finding, "nist_ai_rmf", [])),
    }


_FIELDNAMES = [
    "target", "scan_date", "finding_id", "title", "severity",
    "status", "agent", "description", "remediation",
    "cvss_score", "ai_risk_score", "owasp_llm", "owasp_agentic", "nist_ai_rmf",
]


def render(report: ScanReport, output_path: Path) -> Path:
    """Render a scan report to a CSV file.

    Args:
        report: The complete scan report.
        output_path: Destination file path.

    Returns:
        The resolved path to the written CSV file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    scan_target = report.target_image or report.target_name
    scan_date = ""
    if report.generated_at:
        scan_date = (
            report.generated_at.isoformat()
            if isinstance(report.generated_at, datetime)
            else str(report.generated_at)
        )

    rows = [_flatten_finding(f, scan_target, scan_date) for f in report.all_findings]

    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    return output_path.resolve()
