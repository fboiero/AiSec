"""Data models for the auto-remediation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4


@dataclass
class CodePatch:
    """A concrete code change suggestion."""

    file_path: str = ""
    language: str = "python"
    before: str = ""
    after: str = ""
    explanation: str = ""


@dataclass
class FixSuggestion:
    """A single remediation suggestion for a finding."""

    id: UUID = field(default_factory=uuid4)
    finding_id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    effort: str = "medium"  # low, medium, high
    priority: int = 1  # 1 = highest
    code_patches: list[CodePatch] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    framework_guidance: dict[str, str] = field(default_factory=dict)


@dataclass
class RemediationPlan:
    """Prioritized remediation plan for all findings in a scan."""

    scan_id: UUID = field(default_factory=uuid4)
    total_findings: int = 0
    total_suggestions: int = 0
    critical_fixes: list[FixSuggestion] = field(default_factory=list)
    high_fixes: list[FixSuggestion] = field(default_factory=list)
    medium_fixes: list[FixSuggestion] = field(default_factory=list)
    low_fixes: list[FixSuggestion] = field(default_factory=list)
    estimated_effort: str = ""
    quick_wins: list[FixSuggestion] = field(default_factory=list)
