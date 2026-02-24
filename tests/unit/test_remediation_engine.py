"""Tests for the auto-remediation engine."""

from __future__ import annotations

import pytest

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.remediation.engine import RemediationEngine
from aisec.remediation.models import CodePatch, FixSuggestion, RemediationPlan
from aisec.remediation.strategies import generate_fix


class TestRemediationModels:
    """Test data models."""

    def test_code_patch_defaults(self):
        patch = CodePatch()
        assert patch.language == "python"
        assert patch.before == ""
        assert patch.after == ""

    def test_fix_suggestion_defaults(self):
        fix = FixSuggestion()
        assert fix.effort == "medium"
        assert fix.priority == 1
        assert fix.code_patches == []
        assert fix.commands == []

    def test_remediation_plan_defaults(self):
        plan = RemediationPlan()
        assert plan.total_findings == 0
        assert plan.critical_fixes == []
        assert plan.quick_wins == []


class TestStrategies:
    """Test fix generation strategies."""

    def test_hardcoded_secret_fix(self):
        fix = generate_fix("Hardcoded API key detected", "Key found in source", "dataflow", "critical")
        assert fix is not None
        assert "environment" in fix.title.lower() or "secret" in fix.title.lower()
        assert len(fix.code_patches) >= 1

    def test_sql_injection_fix(self):
        fix = generate_fix("SQL injection in tool function", "Format string", "tool_chain", "critical")
        assert fix is not None
        assert "parameterized" in fix.title.lower() or "sql" in fix.description.lower()

    def test_missing_guardrails_fix(self):
        fix = generate_fix("No guardrail framework detected", "Missing guardrails", "guardrails", "high")
        assert fix is not None
        assert len(fix.code_patches) >= 1

    def test_pii_exposure_fix(self):
        fix = generate_fix("PII data exposure in logs", "Email found", "dataflow", "high")
        assert fix is not None
        assert "pii" in fix.title.lower() or "scrub" in fix.description.lower()

    def test_rate_limiting_fix(self):
        fix = generate_fix("No rate limiting on API", "Missing rate limit", "api_security", "medium")
        assert fix is not None

    def test_mcp_auth_fix(self):
        fix = generate_fix("Unauthenticated MCP server", "No auth", "mcp_security", "critical")
        assert fix is not None
        assert "mcp" in fix.title.lower() or "auth" in fix.title.lower()

    def test_generic_fallback(self):
        fix = generate_fix("Some unknown finding type XYZ", "Something weird", "unknown", "low")
        assert fix is not None
        assert "remediate" in fix.title.lower()

    def test_deserialization_fix(self):
        fix = generate_fix("Unsafe deserialization: pickle.load", "Pickle detected", "serialization", "critical")
        assert fix is not None

    def test_rag_fix(self):
        fix = generate_fix("No retrieval result filtering", "Raw results", "rag_security", "high")
        assert fix is not None

    def test_memory_fix(self):
        fix = generate_fix("Unbounded memory growth", "No limit", "agent_memory", "medium")
        assert fix is not None


class TestRemediationEngine:
    """Test the engine orchestration."""

    def _make_findings(self) -> list[Finding]:
        return [
            Finding(title="Hardcoded API key", description="Key", severity=Severity.CRITICAL, agent="dataflow"),
            Finding(title="No guardrail framework", description="Missing", severity=Severity.HIGH, agent="guardrails"),
            Finding(title="No rate limiting", description="None", severity=Severity.MEDIUM, agent="api_security"),
            Finding(title="Unpinned dependencies", description="Loose", severity=Severity.LOW, agent="supply_chain"),
        ]

    def test_generate_plan_counts(self):
        engine = RemediationEngine()
        plan = engine.generate_plan(self._make_findings())
        assert plan.total_findings == 4
        assert plan.total_suggestions == 4
        assert len(plan.critical_fixes) == 1
        assert len(plan.high_fixes) == 1
        assert len(plan.medium_fixes) == 1
        assert len(plan.low_fixes) == 1

    def test_quick_wins_identified(self):
        engine = RemediationEngine()
        plan = engine.generate_plan(self._make_findings())
        assert len(plan.quick_wins) >= 1
        for qw in plan.quick_wins:
            assert qw.effort == "low"

    def test_estimated_effort(self):
        engine = RemediationEngine()
        plan = engine.generate_plan(self._make_findings())
        assert plan.estimated_effort != ""
        assert "hour" in plan.estimated_effort or "day" in plan.estimated_effort

    def test_empty_findings(self):
        engine = RemediationEngine()
        plan = engine.generate_plan([])
        assert plan.total_findings == 0
        assert plan.total_suggestions == 0
        assert plan.quick_wins == []

    def test_to_markdown(self):
        engine = RemediationEngine()
        plan = engine.generate_plan(self._make_findings())
        md = engine.to_markdown(plan)
        assert "# Remediation Plan" in md
        assert "Quick Wins" in md or "Critical" in md
        assert "Findings:" in md
