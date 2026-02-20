"""Hook specifications for plugin extensibility."""

from __future__ import annotations

from typing import Any

from aisec.core.models import Finding, ScanReport


class HookSpec:
    """Hook specifications that plugins can implement."""

    @staticmethod
    def pre_scan(context: Any) -> None:
        """Called before the scan begins."""

    @staticmethod
    def post_scan(context: Any, report: ScanReport) -> None:
        """Called after the scan completes."""

    @staticmethod
    def on_finding(finding: Finding) -> Finding | None:
        """Called when a new finding is created. Return None to suppress."""
        return finding

    @staticmethod
    def modify_report(report: ScanReport) -> ScanReport:
        """Called before report rendering. Allows modification."""
        return report
