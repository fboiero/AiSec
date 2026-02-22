"""Tests for DataLineagePrivacyAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.data_lineage import (
    ANONYMIZATION_PATTERNS,
    CONSENT_PATTERNS,
    DELETION_PATTERNS,
    LLM_API_PATTERNS,
    PII_VAR_PATTERNS,
    DataLineagePrivacyAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestDataLineageMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert DataLineagePrivacyAgent.name == "data_lineage"

    def test_phase(self):
        assert DataLineagePrivacyAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM06" in DataLineagePrivacyAgent.frameworks
        assert "ASI06" in DataLineagePrivacyAgent.frameworks

    def test_depends_on(self):
        assert "dataflow" in DataLineagePrivacyAgent.depends_on
        assert "privacy" in DataLineagePrivacyAgent.depends_on


class TestPIIPatterns:
    """Test PII detection patterns."""

    def test_pii_var_matches(self):
        assert PII_VAR_PATTERNS.search("user_email = form.email")
        assert PII_VAR_PATTERNS.search("ssn = request.form['ssn']")
        assert PII_VAR_PATTERNS.search("patient_name = record.first_name")

    def test_llm_api_matches(self):
        assert LLM_API_PATTERNS.search("client.chat.completions.create(")
        assert LLM_API_PATTERNS.search("anthropic.messages.create(")

    def test_anonymization_matches(self):
        assert ANONYMIZATION_PATTERNS.search("anonymize(data)")
        assert ANONYMIZATION_PATTERNS.search("from presidio import analyzer")
        assert ANONYMIZATION_PATTERNS.search("mask(pii_text)")

    def test_consent_matches(self):
        assert CONSENT_PATTERNS.search("user_consent = True")
        assert CONSENT_PATTERNS.search("if gdpr_consent:")
        assert CONSENT_PATTERNS.search("opt_in = request.form['opt_in']")

    def test_deletion_matches(self):
        assert DELETION_PATTERNS.search("def delete_user(user_id):")
        assert DELETION_PATTERNS.search("right_to_erasure(user)")
        assert DELETION_PATTERNS.search("user.delete()")


class TestDataLineageNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestPIIToLLM:
    """Test PII to LLM detection."""

    def test_detects_pii_near_llm_calls(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        files = {
            "/app/main.py": (
                'user_email = form.email\n'
                'response = client.chat.completions.create(\n'
                '    messages=[{"role": "user", "content": user_email}]\n'
                ')\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_pii_to_llm(files, combined)
        pii_findings = [f for f in agent.findings if "PII" in f.title]
        assert len(pii_findings) >= 1

    def test_no_finding_without_llm_calls(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        files = {
            "/app/main.py": (
                'user_email = form.email\n'
                'print(user_email)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_pii_to_llm(files, combined)
        pii_findings = [f for f in agent.findings if "PII" in f.title]
        assert len(pii_findings) == 0


class TestConsentMechanism:
    """Test consent mechanism detection."""

    def test_no_consent_detected(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        code = 'user_email = form.email\nprocess(user_email)\n'
        agent._check_consent_mechanism(code)
        consent_findings = [f for f in agent.findings if "consent" in f.title.lower()]
        assert len(consent_findings) >= 1

    def test_consent_present_ok(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        code = 'user_email = form.email\nif user_consent:\n    process(email)\n'
        agent._check_consent_mechanism(code)
        consent_findings = [f for f in agent.findings if "consent" in f.title.lower()]
        assert len(consent_findings) == 0


class TestErasureMechanism:
    """Test right-to-erasure detection."""

    def test_no_erasure_detected(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        code = 'user_email = form.email\nstore(email)\n'
        agent._check_erasure_mechanism(code)
        erasure_findings = [f for f in agent.findings if "erasure" in f.title.lower()]
        assert len(erasure_findings) >= 1

    def test_erasure_present_ok(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        code = (
            'user_email = form.email\n'
            'def delete_user(user_id):\n'
            '    db.delete(user_id)\n'
        )
        agent._check_erasure_mechanism(code)
        erasure_findings = [f for f in agent.findings if "erasure" in f.title.lower()]
        assert len(erasure_findings) == 0


class TestPIIInLogs:
    """Test PII in logs detection."""

    def test_detects_pii_in_logs(self, scan_context):
        agent = DataLineagePrivacyAgent(scan_context)
        files = {
            "/app/main.py": (
                'logger.info("User email: %s", user.email)\n'
                'print(f"Password: {password}")\n'
            )
        }
        agent._check_pii_in_logs(files)
        log_findings = [f for f in agent.findings if "log" in f.title.lower()]
        assert len(log_findings) >= 1
