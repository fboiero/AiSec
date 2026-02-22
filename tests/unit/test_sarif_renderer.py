"""Tests for the SARIF v2.1.0 report renderer."""

import json
import tempfile
from pathlib import Path
from uuid import UUID, uuid4

from aisec.core.enums import FindingStatus, Severity
from aisec.core.models import (
    AgentResult,
    Evidence,
    ExecutiveSummary,
    Finding,
    RiskOverview,
    ScanReport,
)
from aisec.reports.renderers import sarif_renderer
from aisec.reports.renderers.sarif_renderer import (
    _build_help_uri,
    _build_locations,
    _build_properties,
    _build_rule_id,
    _sanitise_rule_name,
    _severity_to_level,
    _severity_to_rank,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    """Create a Finding with sensible defaults, allowing overrides."""
    defaults = dict(
        title="Test Finding",
        description="A test finding description",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        agent="test_agent",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_report(**overrides) -> ScanReport:
    """Create a minimal ScanReport for render() tests."""
    finding = _make_finding(
        owasp_llm=["LLM01"],
        remediation="Apply input validation.",
        references=["https://example.com/ref"],
        evidence=[
            Evidence(type="api_response", summary="Prompt leak detected", location="/app/main.py"),
        ],
        cvss_score=8.5,
        ai_risk_score=75.0,
    )
    defaults = dict(
        target_name="test-target",
        target_image="test:latest",
        aisec_version="0.1.0",
        language="en",
        executive_summary=ExecutiveSummary(
            overall_risk_level=Severity.HIGH,
            total_findings=1,
            high_count=1,
            summary_text="1 high finding.",
        ),
        risk_overview=RiskOverview(ai_risk_score=70.0),
        agent_results={"test_agent": AgentResult(agent="test_agent", findings=[finding])},
        all_findings=[finding],
    )
    defaults.update(overrides)
    return ScanReport(**defaults)


# ---------------------------------------------------------------------------
# _severity_to_level
# ---------------------------------------------------------------------------


class TestSeverityToLevel:
    def test_critical_maps_to_error(self):
        assert _severity_to_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_level(Severity.LOW) == "note"

    def test_info_maps_to_note(self):
        assert _severity_to_level(Severity.INFO) == "note"


# ---------------------------------------------------------------------------
# _severity_to_rank
# ---------------------------------------------------------------------------


class TestSeverityToRank:
    def test_critical_rank(self):
        assert _severity_to_rank(Severity.CRITICAL) == 95.0

    def test_high_rank(self):
        assert _severity_to_rank(Severity.HIGH) == 80.0

    def test_medium_rank(self):
        assert _severity_to_rank(Severity.MEDIUM) == 60.0

    def test_low_rank(self):
        assert _severity_to_rank(Severity.LOW) == 30.0

    def test_info_rank(self):
        assert _severity_to_rank(Severity.INFO) == 10.0

    def test_rank_ordering(self):
        """Higher severity must have strictly higher rank."""
        ranks = [
            _severity_to_rank(Severity.INFO),
            _severity_to_rank(Severity.LOW),
            _severity_to_rank(Severity.MEDIUM),
            _severity_to_rank(Severity.HIGH),
            _severity_to_rank(Severity.CRITICAL),
        ]
        assert ranks == sorted(ranks), "Ranks should be strictly ascending"


# ---------------------------------------------------------------------------
# _build_rule_id
# ---------------------------------------------------------------------------


class TestBuildRuleId:
    def test_prefers_owasp_llm(self):
        finding = _make_finding(
            owasp_llm=["LLM01"],
            owasp_agentic=["ASI02"],
            nist_ai_rmf=["GOVERN"],
        )
        assert _build_rule_id(finding) == "LLM01"

    def test_falls_back_to_owasp_agentic(self):
        finding = _make_finding(
            owasp_llm=[],
            owasp_agentic=["ASI02"],
            nist_ai_rmf=["GOVERN"],
        )
        assert _build_rule_id(finding) == "ASI02"

    def test_falls_back_to_nist(self):
        finding = _make_finding(
            owasp_llm=[],
            owasp_agentic=[],
            nist_ai_rmf=["GOVERN"],
        )
        assert _build_rule_id(finding) == "GOVERN"

    def test_falls_back_to_uuid_prefix(self):
        finding = _make_finding(
            owasp_llm=[],
            owasp_agentic=[],
            nist_ai_rmf=[],
        )
        rule_id = _build_rule_id(finding)
        assert rule_id.startswith("AISEC-")
        # The UUID prefix portion should be uppercase hex
        uuid_prefix = rule_id.replace("AISEC-", "")
        assert uuid_prefix == str(finding.id).split("-")[0].upper()

    def test_strips_whitespace_from_owasp_llm(self):
        finding = _make_finding(owasp_llm=["  LLM01  "])
        assert _build_rule_id(finding) == "LLM01"

    def test_uses_first_element_only(self):
        finding = _make_finding(owasp_llm=["LLM01", "LLM02"])
        assert _build_rule_id(finding) == "LLM01"


# ---------------------------------------------------------------------------
# _build_help_uri
# ---------------------------------------------------------------------------


class TestBuildHelpUri:
    def test_prefers_references(self):
        finding = _make_finding(
            references=["https://example.com/vuln/123"],
            owasp_llm=["LLM01"],
        )
        assert _build_help_uri(finding) == "https://example.com/vuln/123"

    def test_falls_back_to_owasp_llm_url(self):
        finding = _make_finding(
            references=[],
            owasp_llm=["LLM01"],
        )
        uri = _build_help_uri(finding)
        assert "owasp.org" in uri
        assert "large-language-model" in uri

    def test_falls_back_to_owasp_agentic_url(self):
        finding = _make_finding(
            references=[],
            owasp_llm=[],
            owasp_agentic=["ASI01"],
        )
        uri = _build_help_uri(finding)
        assert "owasp.org" in uri
        assert "agentic" in uri

    def test_falls_back_to_default_url(self):
        finding = _make_finding(
            references=[],
            owasp_llm=[],
            owasp_agentic=[],
            nist_ai_rmf=[],
        )
        uri = _build_help_uri(finding)
        assert uri == "https://github.com/aisec-project/aisec"


# ---------------------------------------------------------------------------
# _sanitise_rule_name
# ---------------------------------------------------------------------------


class TestSanitiseRuleName:
    def test_short_name_unchanged(self):
        assert _sanitise_rule_name("PromptInjection") == "PromptInjection"

    def test_newlines_replaced_with_space(self):
        assert _sanitise_rule_name("Line1\nLine2\rLine3") == "Line1 Line2 Line3"

    def test_truncation_at_200_chars(self):
        long_name = "A" * 300
        result = _sanitise_rule_name(long_name)
        assert len(result) == 200
        assert result.endswith("...")
        assert result == "A" * 197 + "..."

    def test_exactly_200_chars_not_truncated(self):
        name = "B" * 200
        assert _sanitise_rule_name(name) == name

    def test_strips_surrounding_whitespace(self):
        assert _sanitise_rule_name("  spaced  ") == "spaced"

    def test_empty_string(self):
        assert _sanitise_rule_name("") == ""


# ---------------------------------------------------------------------------
# _build_locations
# ---------------------------------------------------------------------------


class TestBuildLocations:
    def test_file_path_evidence(self):
        finding = _make_finding(
            evidence=[
                Evidence(type="file_content", summary="Found secret", location="/etc/config.yaml"),
            ],
        )
        locations = _build_locations(finding)
        assert len(locations) == 1
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "/etc/config.yaml"
        assert phys["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert locations[0]["message"]["text"] == "Found secret"

    def test_url_evidence(self):
        finding = _make_finding(
            evidence=[
                Evidence(type="api_response", summary="Endpoint exposed", location="https://api.example.com/v1/data"),
            ],
        )
        locations = _build_locations(finding)
        assert len(locations) == 1
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "https://api.example.com/v1/data"
        assert "uriBaseId" not in phys["artifactLocation"]

    def test_http_url_evidence(self):
        finding = _make_finding(
            evidence=[
                Evidence(type="api_response", summary="HTTP endpoint", location="http://api.internal/check"),
            ],
        )
        locations = _build_locations(finding)
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "http://api.internal/check"
        assert "uriBaseId" not in phys["artifactLocation"]

    def test_dotted_path_gets_srcroot(self):
        """A location like 'app/models.py' contains a dot, so gets %SRCROOT%."""
        finding = _make_finding(
            evidence=[
                Evidence(type="file_content", summary="Issue", location="app/models.py"),
            ],
        )
        locations = _build_locations(finding)
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_no_evidence_location_produces_placeholder(self):
        finding = _make_finding(
            description="Some finding",
            evidence=[
                Evidence(type="log_entry", summary="A log", location=""),
            ],
        )
        locations = _build_locations(finding)
        assert len(locations) == 1
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "aisec-scan"
        assert phys["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_empty_evidence_list_produces_placeholder(self):
        finding = _make_finding(
            title="No Evidence Finding",
            description="Description here",
            evidence=[],
        )
        locations = _build_locations(finding)
        assert len(locations) == 1
        assert locations[0]["message"]["text"] == "Description here"

    def test_multiple_evidence_entries(self):
        finding = _make_finding(
            evidence=[
                Evidence(type="file_content", summary="First", location="/a.py"),
                Evidence(type="file_content", summary="Second", location="/b.py"),
            ],
        )
        locations = _build_locations(finding)
        assert len(locations) == 2

    def test_generic_location_no_dot_no_slash(self):
        """A location like 'container-path' that is not a URL or file path."""
        finding = _make_finding(
            evidence=[
                Evidence(type="config", summary="Config issue", location="redis-container"),
            ],
        )
        locations = _build_locations(finding)
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "redis-container"
        assert "uriBaseId" not in phys["artifactLocation"]


# ---------------------------------------------------------------------------
# _build_properties
# ---------------------------------------------------------------------------


class TestBuildProperties:
    def test_includes_severity_and_status(self):
        finding = _make_finding(severity=Severity.CRITICAL, status=FindingStatus.OPEN)
        props = _build_properties(finding)
        assert props["severity"] == "critical"
        assert props["status"] == "open"

    def test_includes_agent_and_finding_id(self):
        finding = _make_finding(agent="prompt_injection_agent")
        props = _build_properties(finding)
        assert props["agent"] == "prompt_injection_agent"
        assert "findingId" in props
        # findingId should be a valid UUID string
        UUID(props["findingId"])

    def test_includes_timestamp(self):
        finding = _make_finding()
        props = _build_properties(finding)
        assert "timestamp" in props
        assert "T" in props["timestamp"]  # ISO format

    def test_includes_cvss_when_present(self):
        finding = _make_finding(cvss_score=9.1)
        props = _build_properties(finding)
        assert props["cvssScore"] == 9.1

    def test_omits_cvss_when_none(self):
        finding = _make_finding(cvss_score=None)
        props = _build_properties(finding)
        assert "cvssScore" not in props

    def test_includes_ai_risk_score_when_present(self):
        finding = _make_finding(ai_risk_score=85.0)
        props = _build_properties(finding)
        assert props["aiRiskScore"] == 85.0

    def test_omits_ai_risk_score_when_none(self):
        finding = _make_finding(ai_risk_score=None)
        props = _build_properties(finding)
        assert "aiRiskScore" not in props

    def test_includes_owasp_llm(self):
        finding = _make_finding(owasp_llm=["LLM01", "LLM02"])
        props = _build_properties(finding)
        assert props["owaspLlmTop10"] == ["LLM01", "LLM02"]

    def test_includes_owasp_agentic(self):
        finding = _make_finding(owasp_agentic=["ASI03"])
        props = _build_properties(finding)
        assert props["owaspAgenticTop10"] == ["ASI03"]

    def test_includes_nist_ai_rmf(self):
        finding = _make_finding(nist_ai_rmf=["GOVERN", "MAP"])
        props = _build_properties(finding)
        assert props["nistAiRmf"] == ["GOVERN", "MAP"]

    def test_includes_remediation(self):
        finding = _make_finding(remediation="Apply the patch.")
        props = _build_properties(finding)
        assert props["remediation"] == "Apply the patch."

    def test_omits_remediation_when_empty(self):
        finding = _make_finding(remediation="")
        props = _build_properties(finding)
        assert "remediation" not in props

    def test_includes_references(self):
        finding = _make_finding(references=["https://example.com"])
        props = _build_properties(finding)
        assert props["references"] == ["https://example.com"]

    def test_includes_metadata(self):
        finding = _make_finding(metadata={"custom_key": "custom_value"})
        props = _build_properties(finding)
        assert props["metadata"] == {"custom_key": "custom_value"}

    def test_omits_metadata_when_empty(self):
        finding = _make_finding(metadata={})
        props = _build_properties(finding)
        assert "metadata" not in props


# ---------------------------------------------------------------------------
# render() - full integration
# ---------------------------------------------------------------------------


class TestRender:
    def test_produces_valid_json(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        assert output.exists()
        data = json.loads(output.read_text())
        assert isinstance(data, dict)

    def test_sarif_version(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_schema(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_runs_array(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        assert "runs" in data
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) == 1

    def test_tool_driver_info(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AiSec"
        assert driver["version"] == "0.1.0"
        assert "informationUri" in driver

    def test_results_present(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "LLM01"
        assert results[0]["level"] == "error"  # HIGH -> error

    def test_rules_present(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "LLM01"

    def test_invocations_present(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        invocations = data["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_creates_parent_directories(self, tmp_path: Path):
        report = _make_report()
        nested = tmp_path / "deep" / "nested" / "dir"
        output = sarif_renderer.render(report, nested / "report.sarif")
        assert output.exists()

    def test_empty_findings_report(self, tmp_path: Path):
        report = _make_report(all_findings=[], agent_results={})
        output = sarif_renderer.render(report, tmp_path / "empty.sarif")
        data = json.loads(output.read_text())
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_multiple_findings(self, tmp_path: Path):
        f1 = _make_finding(
            title="Finding One",
            severity=Severity.CRITICAL,
            owasp_llm=["LLM01"],
        )
        f2 = _make_finding(
            title="Finding Two",
            severity=Severity.LOW,
            owasp_agentic=["ASI05"],
        )
        report = _make_report(
            all_findings=[f1, f2],
            executive_summary=ExecutiveSummary(
                overall_risk_level=Severity.CRITICAL,
                total_findings=2,
                critical_count=1,
                low_count=1,
            ),
        )
        output = sarif_renderer.render(report, tmp_path / "multi.sarif")
        data = json.loads(output.read_text())
        assert len(data["runs"][0]["results"]) == 2
        rule_ids = [r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]]
        assert "LLM01" in rule_ids
        assert "ASI05" in rule_ids

    def test_output_with_tempfile(self):
        """Verify render works with a tempfile path."""
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "scan.sarif"
            result = sarif_renderer.render(report, out_path)
            assert result.exists()
            data = json.loads(result.read_text())
            assert data["version"] == "2.1.0"

    def test_executive_summary_in_properties(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        run_props = data["runs"][0]["properties"]
        assert "executiveSummary" in run_props
        assert run_props["executiveSummary"]["highCount"] == 1

    def test_risk_overview_in_properties(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        run_props = data["runs"][0]["properties"]
        assert "riskOverview" in run_props
        assert run_props["riskOverview"]["aiRiskScore"] == 70.0

    def test_original_uri_base_ids(self, tmp_path: Path):
        report = _make_report()
        output = sarif_renderer.render(report, tmp_path / "report.sarif")
        data = json.loads(output.read_text())
        base_ids = data["runs"][0]["originalUriBaseIds"]
        assert "%SRCROOT%" in base_ids
