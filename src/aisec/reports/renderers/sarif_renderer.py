"""SARIF v2.1.0 report renderer for IDE and CI integration.

Serialises a :class:`~aisec.core.models.ScanReport` to the Static Analysis
Results Interchange Format (SARIF) v2.1.0, enabling consumption by GitHub
Code Scanning, VS Code SARIF Viewer, Azure DevOps, and other SARIF-aware
tools.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from aisec.core.enums import Severity
from aisec.core.models import Evidence, Finding, ScanReport


# ---------------------------------------------------------------------------
# SARIF schema constants
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "AiSec"
_TOOL_INFORMATION_URI = "https://github.com/aisec-project/aisec"


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


# ---------------------------------------------------------------------------
# Custom JSON encoder
# ---------------------------------------------------------------------------

class _SarifEncoder(json.JSONEncoder):
    """JSON encoder that handles AiSec domain types for SARIF output."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        return super().default(obj)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _severity_to_level(severity: Severity) -> str:
    """Map an AiSec severity to a SARIF level string.

    Args:
        severity: The finding severity.

    Returns:
        One of ``"error"``, ``"warning"``, or ``"note"``.
    """
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "note")


def _severity_to_rank(severity: Severity) -> float:
    """Map a severity to a SARIF rank (0.0 - 100.0) for sorting.

    Args:
        severity: The finding severity.

    Returns:
        A numeric rank where higher means more severe.
    """
    mapping: dict[Severity, float] = {
        Severity.CRITICAL: 95.0,
        Severity.HIGH: 80.0,
        Severity.MEDIUM: 60.0,
        Severity.LOW: 30.0,
        Severity.INFO: 10.0,
    }
    return mapping.get(severity, 0.0)


def _build_rule_id(finding: Finding) -> str:
    """Derive a stable rule identifier from a finding.

    Prefers the first OWASP LLM category, then OWASP Agentic, then NIST,
    then falls back to the finding UUID.

    Args:
        finding: The finding to derive a rule ID from.

    Returns:
        A string suitable for use as a SARIF ``ruleId``.
    """
    if finding.owasp_llm:
        return finding.owasp_llm[0].strip()
    if finding.owasp_agentic:
        return finding.owasp_agentic[0].strip()
    if finding.nist_ai_rmf:
        return finding.nist_ai_rmf[0].strip()
    return f"AISEC-{str(finding.id).split('-')[0].upper()}"


def _build_help_uri(finding: Finding) -> str:
    """Construct a help URI for a finding's rule.

    Args:
        finding: The finding to derive a help URI from.

    Returns:
        A URL string pointing to relevant documentation.
    """
    if finding.references:
        return finding.references[0]
    if finding.owasp_llm:
        return "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    if finding.owasp_agentic:
        return "https://owasp.org/www-project-agentic-security-initiative/"
    return "https://github.com/aisec-project/aisec"


def _build_locations(finding: Finding) -> list[dict[str, Any]]:
    """Build SARIF location objects from a finding's evidence.

    Each piece of evidence with a non-empty ``location`` field is mapped
    to a SARIF ``physicalLocation``.  If no evidence has a location, a
    single location with a message is produced.

    Args:
        finding: The finding whose evidence provides location data.

    Returns:
        A list of SARIF location dictionaries.
    """
    locations: list[dict[str, Any]] = []

    for ev in finding.evidence:
        if ev.location:
            location_entry: dict[str, Any] = {}

            # Determine if the location looks like a file path or a URL
            if ev.location.startswith(("http://", "https://")):
                location_entry["physicalLocation"] = {
                    "artifactLocation": {
                        "uri": ev.location,
                    },
                }
            elif ev.location.startswith("/") or "." in ev.location:
                location_entry["physicalLocation"] = {
                    "artifactLocation": {
                        "uri": ev.location,
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            else:
                # Generic location (e.g., container path, config key)
                location_entry["physicalLocation"] = {
                    "artifactLocation": {
                        "uri": ev.location,
                    },
                }

            # Add the evidence summary as a message on the location
            if ev.summary:
                location_entry["message"] = {"text": ev.summary}

            locations.append(location_entry)

    # If no evidence had a location, provide a placeholder
    if not locations:
        locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "aisec-scan",
                    "uriBaseId": "%SRCROOT%",
                },
            },
            "message": {
                "text": finding.description or finding.title or "No location available",
            },
        })

    return locations


def _build_properties(finding: Finding) -> dict[str, Any]:
    """Build the SARIF ``properties`` bag for a finding result.

    This includes AI-specific metadata not captured by standard SARIF fields.

    Args:
        finding: The finding to extract properties from.

    Returns:
        A dictionary of additional properties.
    """
    props: dict[str, Any] = {}

    if finding.cvss_score is not None:
        props["cvssScore"] = finding.cvss_score

    if finding.ai_risk_score is not None:
        props["aiRiskScore"] = finding.ai_risk_score

    if finding.owasp_llm:
        props["owaspLlmTop10"] = finding.owasp_llm

    if finding.owasp_agentic:
        props["owaspAgenticTop10"] = finding.owasp_agentic

    if finding.nist_ai_rmf:
        props["nistAiRmf"] = finding.nist_ai_rmf

    props["severity"] = finding.severity.value
    props["status"] = finding.status.value
    props["agent"] = finding.agent
    props["findingId"] = str(finding.id)
    props["timestamp"] = finding.timestamp.isoformat()

    if finding.remediation:
        props["remediation"] = finding.remediation

    if finding.references:
        props["references"] = finding.references

    if finding.metadata:
        props["metadata"] = _to_serializable(finding.metadata)

    return props


def _build_rule(
    rule_id: str,
    finding: Finding,
) -> dict[str, Any]:
    """Build a SARIF rule definition from a finding.

    Args:
        rule_id: The rule identifier.
        finding: A representative finding for this rule.

    Returns:
        A SARIF rule dictionary.
    """
    # Determine rule name from title or rule ID
    rule_name = finding.title or rule_id

    # Build short description
    short_desc = finding.title or f"AiSec finding: {rule_id}"

    # Build full description
    full_desc = finding.description or short_desc

    # Build help URI
    help_uri = _build_help_uri(finding)

    # Build rule properties
    rule_properties: dict[str, Any] = {
        "severity": finding.severity.value,
    }
    if finding.owasp_llm:
        rule_properties["owaspLlmTop10"] = finding.owasp_llm
    if finding.owasp_agentic:
        rule_properties["owaspAgenticTop10"] = finding.owasp_agentic
    if finding.nist_ai_rmf:
        rule_properties["nistAiRmf"] = finding.nist_ai_rmf
    if finding.cvss_score is not None:
        rule_properties["cvssScore"] = finding.cvss_score

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _sanitise_rule_name(rule_name),
        "shortDescription": {
            "text": short_desc,
        },
        "fullDescription": {
            "text": full_desc,
        },
        "helpUri": help_uri,
        "properties": rule_properties,
        "defaultConfiguration": {
            "level": _severity_to_level(finding.severity),
            "rank": _severity_to_rank(finding.severity),
        },
    }

    return rule


def _sanitise_rule_name(name: str) -> str:
    """Sanitise a string for use as a SARIF rule name.

    Rule names should be concise and not contain newlines.

    Args:
        name: The raw name string.

    Returns:
        A sanitised name string.
    """
    sanitised = name.replace("\n", " ").replace("\r", " ").strip()
    if len(sanitised) > 200:
        sanitised = sanitised[:197] + "..."
    return sanitised


def _build_result(
    finding: Finding,
    rule_id: str,
    rule_index: int,
) -> dict[str, Any]:
    """Build a SARIF result object from a finding.

    Args:
        finding: The security finding.
        rule_id: The rule identifier for this finding.
        rule_index: The index of the rule in the ``tool.driver.rules`` array.

    Returns:
        A SARIF result dictionary.
    """
    # Build the message text
    message_parts: list[str] = []
    if finding.title:
        message_parts.append(finding.title)
    if finding.description:
        message_parts.append(finding.description)
    if finding.remediation:
        message_parts.append(f"Remediation: {finding.remediation}")
    message_text = "\n\n".join(message_parts) if message_parts else "No description available"

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _severity_to_level(finding.severity),
        "message": {
            "text": message_text,
        },
        "locations": _build_locations(finding),
        "properties": _build_properties(finding),
    }

    # Add fingerprints for deduplication
    result["fingerprints"] = {
        "aisecFindingId/v1": str(finding.id),
    }

    # Add partial fingerprints based on content
    partial: dict[str, str] = {}
    if finding.title:
        partial["titleHash/v1"] = str(hash(finding.title) & 0xFFFFFFFF)
    if finding.description:
        partial["descriptionHash/v1"] = str(
            hash(finding.description) & 0xFFFFFFFF
        )
    if partial:
        result["partialFingerprints"] = partial

    # Add related locations from evidence
    related_locations = _build_related_locations(finding)
    if related_locations:
        result["relatedLocations"] = related_locations

    # Add fixes if remediation is available
    if finding.remediation:
        result["fixes"] = [
            {
                "description": {
                    "text": finding.remediation,
                },
            }
        ]

    return result


def _build_related_locations(
    finding: Finding,
) -> list[dict[str, Any]]:
    """Build related location objects from evidence beyond the primary.

    Args:
        finding: The finding with evidence.

    Returns:
        A list of SARIF relatedLocation dictionaries.
    """
    related: list[dict[str, Any]] = []
    for idx, ev in enumerate(finding.evidence):
        if ev.summary or ev.raw_data:
            entry: dict[str, Any] = {
                "id": idx,
                "message": {
                    "text": ev.summary or f"Evidence type: {ev.type}",
                },
            }
            if ev.location:
                if ev.location.startswith(("http://", "https://")):
                    entry["physicalLocation"] = {
                        "artifactLocation": {
                            "uri": ev.location,
                        },
                    }
                else:
                    entry["physicalLocation"] = {
                        "artifactLocation": {
                            "uri": ev.location,
                            "uriBaseId": "%SRCROOT%",
                        },
                    }
            related.append(entry)
    return related


def _build_invocation(report: ScanReport) -> dict[str, Any]:
    """Build a SARIF invocation object from the scan report.

    Args:
        report: The scan report.

    Returns:
        A SARIF invocation dictionary.
    """
    has_errors = report.executive_summary.critical_count > 0

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "commandLine": f"aisec scan {report.target_name}",
        "properties": {
            "scanId": str(report.scan_id),
            "targetName": report.target_name,
            "targetImage": report.target_image,
            "scanDurationSeconds": report.scan_duration_seconds,
            "language": report.language,
        },
    }

    if report.generated_at:
        invocation["startTimeUtc"] = report.generated_at.isoformat()

    if has_errors:
        invocation["toolExecutionNotifications"] = [
            {
                "message": {
                    "text": (
                        f"Scan completed with "
                        f"{report.executive_summary.critical_count} critical "
                        f"finding(s) requiring immediate attention."
                    ),
                },
                "level": "error",
            }
        ]

    return invocation


def _to_serializable(obj: Any) -> Any:
    """Recursively convert an object tree to JSON-serializable primitives."""
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return _to_serializable(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(item) for item in obj]
    return obj


def _build_sarif_document(report: ScanReport) -> dict[str, Any]:
    """Build the complete SARIF document from a scan report.

    Args:
        report: The scan report to convert.

    Returns:
        A dictionary representing the full SARIF JSON structure.
    """
    # Collect all findings
    all_findings = report.all_findings

    # Build rules and results, tracking unique rules by rule ID
    rules: list[dict[str, Any]] = []
    rule_id_to_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in all_findings:
        rule_id = _build_rule_id(finding)

        # Register the rule if not already seen
        if rule_id not in rule_id_to_index:
            rule_index = len(rules)
            rule_id_to_index[rule_id] = rule_index
            rules.append(_build_rule(rule_id, finding))
        else:
            rule_index = rule_id_to_index[rule_id]

        # Build the result
        results.append(_build_result(finding, rule_id, rule_index))

    # Resolve version
    version = report.aisec_version or "unknown"

    # Build the tool driver
    driver: dict[str, Any] = {
        "name": _TOOL_NAME,
        "version": version,
        "semanticVersion": version,
        "informationUri": _TOOL_INFORMATION_URI,
        "rules": rules,
        "properties": {
            "reportId": str(report.report_id),
            "scanId": str(report.scan_id),
            "generatedAt": report.generated_at.isoformat(),
        },
    }

    # Build the run
    run: dict[str, Any] = {
        "tool": {
            "driver": driver,
        },
        "results": results,
        "invocations": [_build_invocation(report)],
    }

    # Add executive summary as a run-level property
    run["properties"] = {
        "executiveSummary": {
            "overallRiskLevel": report.executive_summary.overall_risk_level.value,
            "totalFindings": report.executive_summary.total_findings,
            "criticalCount": report.executive_summary.critical_count,
            "highCount": report.executive_summary.high_count,
            "mediumCount": report.executive_summary.medium_count,
            "lowCount": report.executive_summary.low_count,
            "infoCount": report.executive_summary.info_count,
            "topRisks": report.executive_summary.top_risks,
            "summaryText": report.executive_summary.summary_text,
        },
        "riskOverview": {
            "aiRiskScore": report.risk_overview.ai_risk_score,
            "attackSurfaceScore": report.risk_overview.attack_surface_score,
            "dataExposureScore": report.risk_overview.data_exposure_score,
            "agencyRiskScore": report.risk_overview.agency_risk_score,
            "supplyChainScore": report.risk_overview.supply_chain_score,
            "complianceScore": report.risk_overview.compliance_score,
        },
        "targetName": report.target_name,
        "targetImage": report.target_image,
        "language": report.language,
    }

    # Add original URI base IDs for path resolution
    run["originalUriBaseIds"] = {
        "%SRCROOT%": {
            "uri": "file:///",
            "description": {
                "text": "The root directory of the scanned target.",
            },
        },
    }

    # Add taxonomy references for OWASP and NIST mappings
    taxonomies = _build_taxonomies(report)
    if taxonomies:
        run["taxonomies"] = taxonomies

    # Build the complete SARIF document
    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }

    return sarif


def _build_taxonomies(report: ScanReport) -> list[dict[str, Any]]:
    """Build SARIF taxonomy references for framework mappings.

    Args:
        report: The scan report with framework findings.

    Returns:
        A list of SARIF taxonomy dictionaries.
    """
    taxonomies: list[dict[str, Any]] = []

    # OWASP LLM Top 10 taxonomy
    if report.owasp_llm_findings:
        owasp_llm_taxa: list[dict[str, Any]] = []
        for category_id in sorted(report.owasp_llm_findings.keys()):
            findings = report.owasp_llm_findings[category_id]
            owasp_llm_taxa.append({
                "id": category_id,
                "name": category_id,
                "shortDescription": {
                    "text": f"OWASP LLM Top 10 category {category_id}",
                },
                "properties": {
                    "findingCount": len(findings),
                },
            })
        taxonomies.append({
            "name": "OWASP Top 10 for LLM Applications",
            "version": "2025",
            "informationUri": (
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
            ),
            "isComprehensive": False,
            "taxa": owasp_llm_taxa,
        })

    # OWASP Agentic Top 10 taxonomy
    if report.owasp_agentic_findings:
        owasp_agentic_taxa: list[dict[str, Any]] = []
        for category_id in sorted(report.owasp_agentic_findings.keys()):
            findings = report.owasp_agentic_findings[category_id]
            owasp_agentic_taxa.append({
                "id": category_id,
                "name": category_id,
                "shortDescription": {
                    "text": f"OWASP Agentic Security category {category_id}",
                },
                "properties": {
                    "findingCount": len(findings),
                },
            })
        taxonomies.append({
            "name": "OWASP Agentic Security Initiative Top 10",
            "version": "2025",
            "informationUri": (
                "https://owasp.org/www-project-agentic-security-initiative/"
            ),
            "isComprehensive": False,
            "taxa": owasp_agentic_taxa,
        })

    # NIST AI RMF taxonomy
    if report.nist_ai_rmf_findings:
        nist_taxa: list[dict[str, Any]] = []
        for function_id in sorted(report.nist_ai_rmf_findings.keys()):
            findings = report.nist_ai_rmf_findings[function_id]
            nist_taxa.append({
                "id": function_id,
                "name": function_id,
                "shortDescription": {
                    "text": f"NIST AI RMF function {function_id}",
                },
                "properties": {
                    "findingCount": len(findings),
                },
            })
        taxonomies.append({
            "name": "NIST AI Risk Management Framework",
            "version": "1.0",
            "informationUri": (
                "https://www.nist.gov/artificial-intelligence/"
                "executive-order-safe-secure-and-trustworthy-artificial-intelligence"
            ),
            "isComprehensive": False,
            "taxa": nist_taxa,
        })

    return taxonomies


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render(report: ScanReport, output_path: Path) -> Path:
    """Render a scan report to a SARIF v2.1.0 JSON file.

    Produces a valid SARIF document suitable for consumption by GitHub Code
    Scanning, VS Code SARIF Viewer, Azure DevOps, and other SARIF-aware
    tools.

    Args:
        report: The complete scan report to serialise.
        output_path: Destination file path.  Parent directories are created
            automatically if they do not exist.  The file extension is
            typically ``.sarif`` or ``.sarif.json``.

    Returns:
        The resolved path to the written SARIF file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sarif_document = _build_sarif_document(report)

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(
            sarif_document,
            fh,
            indent=2,
            ensure_ascii=False,
            cls=_SarifEncoder,
        )
        fh.write("\n")

    return output_path.resolve()
