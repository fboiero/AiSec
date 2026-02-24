"""Tests for FalcoAlertParser (v1.7.0)."""

from __future__ import annotations

import json

import pytest

from aisec.agents.falco_alert_parser import (
    FalcoAlert,
    FalcoAlertParser,
    RULE_SEVERITY_MAP,
    _PRIORITY_TO_SEVERITY,
    _get_remediation,
    _severity_to_cvss,
    _severity_to_ai_risk,
)
from aisec.core.enums import Severity


@pytest.fixture
def parser():
    return FalcoAlertParser()


class TestFalcoAlertParsing:
    def test_parse_valid_json_line(self, parser):
        line = json.dumps({
            "rule": "AI Model File Tampering",
            "priority": "CRITICAL",
            "output": "AI model file modified (file=/tmp/model.pt)",
            "output_fields": {"fd.name": "/tmp/model.pt", "proc.name": "python"},
            "time": "2026-02-23T10:00:00Z",
            "tags": ["aisec", "ai_model"],
        })
        alert = parser.parse_json_line(line)
        assert alert is not None
        assert alert.rule == "AI Model File Tampering"
        assert alert.priority == "CRITICAL"
        assert alert.output_fields["fd.name"] == "/tmp/model.pt"

    def test_parse_empty_line(self, parser):
        assert parser.parse_json_line("") is None
        assert parser.parse_json_line("   ") is None

    def test_parse_invalid_json(self, parser):
        assert parser.parse_json_line("not json at all") is None

    def test_parse_json_missing_fields(self, parser):
        line = json.dumps({"rule": "Test Rule"})
        alert = parser.parse_json_line(line)
        assert alert is not None
        assert alert.rule == "Test Rule"
        assert alert.priority == ""
        assert alert.output == ""

    def test_parse_output_multiple_lines(self, parser):
        lines = "\n".join([
            json.dumps({"rule": "AI Model File Tampering", "priority": "CRITICAL", "output": "alert1"}),
            json.dumps({"rule": "Cryptocurrency Mining Activity", "priority": "CRITICAL", "output": "alert2"}),
            "",
            "some non-json log line",
            json.dumps({"rule": "Container Escape Attempt", "priority": "CRITICAL", "output": "alert3"}),
        ])
        alerts = parser.parse_output(lines)
        assert len(alerts) == 3
        assert alerts[0].rule == "AI Model File Tampering"
        assert alerts[1].rule == "Cryptocurrency Mining Activity"
        assert alerts[2].rule == "Container Escape Attempt"

    def test_parse_output_empty(self, parser):
        assert parser.parse_output("") == []
        assert parser.parse_output("\n\n") == []


class TestAlertToFinding:
    def test_known_rule_mapping(self, parser):
        alert = FalcoAlert(
            rule="AI Model File Tampering",
            priority="CRITICAL",
            output="AI model file modified (file=/tmp/model.pt)",
            output_fields={"fd.name": "/tmp/model.pt", "proc.name": "python", "container.id": "abc123"},
        )
        finding = parser.to_finding(alert)
        assert finding.severity == Severity.CRITICAL
        assert "LLM06" in finding.owasp_llm
        assert "ASI02" in finding.owasp_agentic
        assert "Falco: AI Model File Tampering" == finding.title
        assert len(finding.evidence) == 1

    def test_unknown_rule_uses_priority(self, parser):
        alert = FalcoAlert(
            rule="Custom Unknown Rule",
            priority="WARNING",
            output="something happened",
            output_fields={},
        )
        finding = parser.to_finding(alert)
        assert finding.severity == Severity.MEDIUM  # WARNING maps to MEDIUM

    def test_crypto_mining_mapping(self, parser):
        alert = FalcoAlert(
            rule="Cryptocurrency Mining Activity",
            priority="CRITICAL",
            output="Cryptocurrency miner detected",
            output_fields={"proc.name": "xmrig", "container.id": "def456"},
        )
        finding = parser.to_finding(alert)
        assert finding.severity == Severity.CRITICAL
        assert "xmrig" in finding.description

    def test_container_escape_mapping(self, parser):
        alert = FalcoAlert(
            rule="Container Escape Attempt",
            priority="CRITICAL",
            output="Container escape attempt",
            output_fields={"fd.name": "/proc/1/ns/mnt", "proc.name": "bash"},
        )
        finding = parser.to_finding(alert)
        assert finding.severity == Severity.CRITICAL
        assert "ASI10" in finding.owasp_agentic


class TestRuleSeverityMap:
    def test_all_rules_have_four_elements(self):
        for rule_name, mapping in RULE_SEVERITY_MAP.items():
            assert len(mapping) == 4, f"Rule {rule_name} missing elements"
            severity, owasp_llm, owasp_agentic, nist = mapping
            assert isinstance(severity, Severity)
            assert isinstance(owasp_llm, list)
            assert isinstance(owasp_agentic, list)
            assert isinstance(nist, list)

    def test_critical_rules(self):
        critical_rules = [
            "AI Model File Tampering",
            "Cryptocurrency Mining Activity",
            "Container Escape Attempt",
            "Reverse Shell Spawned",
        ]
        for rule in critical_rules:
            assert RULE_SEVERITY_MAP[rule][0] == Severity.CRITICAL


class TestHelperFunctions:
    def test_remediation_known_rules(self):
        assert "read-only" in _get_remediation("AI Model File Tampering")
        assert "Terminate" in _get_remediation("Cryptocurrency Mining Activity")

    def test_remediation_unknown_rule(self):
        assert "Investigate" in _get_remediation("Nonexistent Rule")

    def test_severity_to_cvss(self):
        assert _severity_to_cvss(Severity.CRITICAL) == 9.5
        assert _severity_to_cvss(Severity.HIGH) == 7.5
        assert _severity_to_cvss(Severity.LOW) == 3.5

    def test_severity_to_ai_risk(self):
        assert _severity_to_ai_risk(Severity.CRITICAL) == 9.0
        assert _severity_to_ai_risk(Severity.INFO) == 1.0

    def test_priority_to_severity_map(self):
        assert _PRIORITY_TO_SEVERITY["EMERGENCY"] == Severity.CRITICAL
        assert _PRIORITY_TO_SEVERITY["WARNING"] == Severity.MEDIUM
        assert _PRIORITY_TO_SEVERITY["NOTICE"] == Severity.LOW
