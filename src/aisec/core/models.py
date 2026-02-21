"""Core domain models for AiSec."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from aisec.core.enums import FindingStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Evidence:
    """A piece of evidence supporting a finding."""

    type: str  # "network_capture", "file_content", "api_response", "log_entry", "config"
    summary: str = ""
    raw_data: str = ""
    location: str = ""  # file path, URL, container path


@dataclass
class Finding:
    """A single security finding discovered by an agent."""

    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    status: FindingStatus = FindingStatus.OPEN
    agent: str = ""
    # Framework mappings
    owasp_llm: list[str] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)
    nist_ai_rmf: list[str] = field(default_factory=list)
    # Evidence
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    ai_risk_score: float | None = None
    timestamp: datetime = field(default_factory=_utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Result produced by a single agent."""

    agent: str = ""
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceCheckItem:
    """A single compliance check item."""

    id: str = ""
    article: str = ""
    requirement: str = ""
    status: str = "n/a"  # pass, fail, partial, n/a
    evidence: str = ""
    related_findings: list[UUID] = field(default_factory=list)


@dataclass
class ComplianceChecklist:
    """Compliance assessment for a single framework."""

    framework_name: str = ""
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    not_applicable: int = 0
    items: list[ComplianceCheckItem] = field(default_factory=list)


@dataclass
class RiskOverview:
    """Composite risk scoring across dimensions."""

    ai_risk_score: float = 0.0
    attack_surface_score: float = 0.0
    data_exposure_score: float = 0.0
    agency_risk_score: float = 0.0
    supply_chain_score: float = 0.0
    compliance_score: float = 0.0


@dataclass
class ExecutiveSummary:
    """Executive summary of scan results."""

    overall_risk_level: Severity = Severity.INFO
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    top_risks: list[str] = field(default_factory=list)
    summary_text: str = ""


@dataclass
class ComplianceReport:
    """Compliance assessment across all frameworks."""

    gdpr: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    ccpa: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    habeas_data: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    eu_ai_act: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    iso_42001: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    nist_ai_600_1: ComplianceChecklist = field(default_factory=ComplianceChecklist)
    argentina_ai: ComplianceChecklist = field(default_factory=ComplianceChecklist)


@dataclass
class ScanReport:
    """Complete scan report."""

    report_id: UUID = field(default_factory=uuid4)
    scan_id: UUID = field(default_factory=uuid4)
    target_name: str = ""
    target_image: str = ""
    aisec_version: str = ""
    generated_at: datetime = field(default_factory=_utcnow)
    scan_duration_seconds: float = 0.0
    language: str = "en"
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    risk_overview: RiskOverview = field(default_factory=RiskOverview)
    owasp_llm_findings: dict[str, list[Finding]] = field(default_factory=dict)
    owasp_agentic_findings: dict[str, list[Finding]] = field(default_factory=dict)
    nist_ai_rmf_findings: dict[str, list[Finding]] = field(default_factory=dict)
    agent_results: dict[str, AgentResult] = field(default_factory=dict)
    compliance: ComplianceReport = field(default_factory=ComplianceReport)
    all_findings: list[Finding] = field(default_factory=list)
