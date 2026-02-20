"""CCPA (California Consumer Privacy Act) compliance checks for AI agents.

This module defines the key CCPA requirements relevant to AI agent systems
and provides an evaluation function that maps security findings and agent
results to a :class:`~aisec.core.models.ComplianceChecklist`.

Reference: https://oag.ca.gov/privacy/ccpa
"""

from __future__ import annotations

from typing import Any

from aisec.core.enums import CheckStatus, ComplianceFramework, Severity
from aisec.core.models import (
    AgentResult,
    ComplianceCheckItem,
    ComplianceChecklist,
    Finding,
)


# ---------------------------------------------------------------------------
# CCPA Compliance Checks
# ---------------------------------------------------------------------------

CCPA_CHECKS: list[dict[str, str]] = [
    # Right to know
    {
        "id": "CCPA-1798.100",
        "article": "Sec. 1798.100",
        "requirement": "Right to know what personal information is collected",
        "description": (
            "Consumers have the right to know what categories and specific "
            "pieces of personal information a business has collected about "
            "them.  AI agents that collect or process personal information "
            "must support disclosure of data categories, sources, purposes, "
            "and third-party sharing practices."
        ),
    },
    {
        "id": "CCPA-1798.110",
        "article": "Sec. 1798.110",
        "requirement": "Right to request disclosure of personal information",
        "description": (
            "Consumers may request that a business disclose the categories "
            "and specific pieces of personal information it has collected, "
            "the categories of sources, the business or commercial purpose, "
            "and the categories of third parties with whom the information "
            "is shared.  AI agent systems must support these requests."
        ),
    },
    # Right to delete
    {
        "id": "CCPA-1798.105",
        "article": "Sec. 1798.105",
        "requirement": "Right to delete personal information",
        "description": (
            "Consumers have the right to request the deletion of their "
            "personal information collected by a business.  AI agent memory "
            "stores, conversation logs, user profiles, and cached data "
            "must support deletion upon verified consumer request."
        ),
    },
    # Right to opt-out of sale
    {
        "id": "CCPA-1798.120",
        "article": "Sec. 1798.120",
        "requirement": "Right to opt-out of sale of personal information",
        "description": (
            "Consumers have the right to direct a business that sells their "
            "personal information to stop selling that information.  AI agent "
            "systems that share personal data with third parties must "
            "implement opt-out mechanisms and honour consumer requests."
        ),
    },
    {
        "id": "CCPA-1798.135",
        "article": "Sec. 1798.135",
        "requirement": "Methods for submitting opt-out requests",
        "description": (
            "Businesses must provide a clear and conspicuous 'Do Not Sell "
            "My Personal Information' link on their website and a mechanism "
            "for consumers to opt out.  AI agent interfaces must include "
            "accessible opt-out options."
        ),
    },
    # Right to non-discrimination
    {
        "id": "CCPA-1798.125",
        "article": "Sec. 1798.125",
        "requirement": "Right to non-discrimination",
        "description": (
            "Businesses may not discriminate against consumers who exercise "
            "their CCPA rights by denying goods or services, charging "
            "different prices, or providing a different level of quality.  "
            "AI agents must not alter their behaviour or service quality "
            "based on whether a consumer has exercised privacy rights."
        ),
    },
    # Notice at collection
    {
        "id": "CCPA-1798.100.b",
        "article": "Sec. 1798.100(b)",
        "requirement": "Notice at collection of personal information",
        "description": (
            "At or before the point of collection, businesses must inform "
            "consumers about the categories of personal information to be "
            "collected and the purposes for which they will be used.  AI "
            "agent interactions that collect personal data must provide "
            "clear notice before or at the time of collection."
        ),
    },
    {
        "id": "CCPA-1798.130",
        "article": "Sec. 1798.130",
        "requirement": "Privacy policy and disclosure requirements",
        "description": (
            "Businesses must make available a privacy policy that lists the "
            "categories of personal information collected, sold, or disclosed "
            "in the preceding 12 months.  AI agent systems must be documented "
            "in the organisation's privacy policy with sufficient detail."
        ),
    },
    # Data security
    {
        "id": "CCPA-1798.150",
        "article": "Sec. 1798.150",
        "requirement": "Data security and breach liability",
        "description": (
            "Consumers may bring a civil action if their nonencrypted and "
            "nonredacted personal information is subject to unauthorised "
            "access as a result of the business's failure to implement and "
            "maintain reasonable security.  AI agent systems must implement "
            "reasonable security measures to protect personal information."
        ),
    },
    {
        "id": "CCPA-1798.81.5",
        "article": "Sec. 1798.81.5",
        "requirement": "Reasonable security measures",
        "description": (
            "Businesses that own, license, or maintain personal information "
            "must implement and maintain reasonable security procedures and "
            "practices appropriate to the nature of the information.  AI "
            "agent infrastructure, APIs, and data stores must meet this "
            "standard."
        ),
    },
    # CPRA amendments -- Right to correct
    {
        "id": "CCPA-1798.106",
        "article": "Sec. 1798.106",
        "requirement": "Right to correct inaccurate personal information",
        "description": (
            "Consumers have the right to request correction of inaccurate "
            "personal information maintained by a business.  AI agent systems "
            "must support mechanisms to rectify personal data upon verified "
            "consumer request."
        ),
    },
    # CPRA amendments -- Right to limit use of sensitive personal information
    {
        "id": "CCPA-1798.121",
        "article": "Sec. 1798.121",
        "requirement": "Right to limit use of sensitive personal information",
        "description": (
            "Consumers have the right to direct a business to limit its use "
            "of their sensitive personal information to that which is "
            "necessary to perform the services or provide the goods "
            "requested.  AI agents processing sensitive data must support "
            "use-limitation requests."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to CCPA checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "CCPA-1798.100": [
        "data collection", "personal information", "data categories",
        "information collected",
    ],
    "CCPA-1798.110": [
        "disclosure request", "data disclosure", "information request",
    ],
    "CCPA-1798.105": [
        "deletion", "erasure", "right to delete", "data removal",
    ],
    "CCPA-1798.120": [
        "sale of data", "opt-out", "data sharing", "third-party sharing",
    ],
    "CCPA-1798.135": [
        "opt-out mechanism", "do not sell", "opt-out link",
    ],
    "CCPA-1798.125": [
        "discrimination", "non-discrimination", "service quality",
        "price difference",
    ],
    "CCPA-1798.100.b": [
        "notice at collection", "collection notice", "data collection notice",
    ],
    "CCPA-1798.130": [
        "privacy policy", "disclosure requirements", "privacy notice",
    ],
    "CCPA-1798.150": [
        "data breach", "unauthorised access", "security breach",
        "data exposure", "data leak",
    ],
    "CCPA-1798.81.5": [
        "security measures", "encryption", "access control",
        "security practices", "data protection",
    ],
    "CCPA-1798.106": [
        "correction", "rectification", "inaccurate data", "data accuracy",
    ],
    "CCPA-1798.121": [
        "sensitive data", "sensitive personal information",
        "use limitation", "restrict processing",
    ],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of CCPA check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_ccpa(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate CCPA compliance based on security findings and agent results.

    This function maps security findings to the relevant CCPA sections and
    produces a :class:`~aisec.core.models.ComplianceChecklist` that
    summarises the compliance posture.

    The evaluation logic:
    - A check **fails** if any finding with severity >= HIGH is matched.
    - A check is **partial** if findings with severity < HIGH are matched.
    - A check **passes** if no findings are matched (indicating no detected
      violations, though this is not a guarantee of compliance).

    Args:
        findings: All security findings from the scan.
        agent_results: Results from individual security agents.

    Returns:
        A populated :class:`~aisec.core.models.ComplianceChecklist` for CCPA.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in CCPA_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in CCPA_CHECKS:
        check_id = check["id"]
        matched = check_findings[check_id]

        if not matched:
            status = CheckStatus.PASS.value
            evidence = "No related findings detected."
            passed += 1
        elif any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in matched
        ):
            status = CheckStatus.FAIL.value
            evidence = (
                f"{len(matched)} finding(s) detected, including high/critical "
                f"severity issues: "
                + ", ".join(f.title for f in matched[:5])
            )
            failed += 1
        else:
            status = CheckStatus.PARTIAL.value
            evidence = (
                f"{len(matched)} finding(s) detected with moderate or lower "
                f"severity: "
                + ", ".join(f.title for f in matched[:5])
            )

        items.append(
            ComplianceCheckItem(
                id=check_id,
                article=check["article"],
                requirement=check["requirement"],
                status=status,
                evidence=evidence,
                related_findings=[f.id for f in matched],
            )
        )

    total = len(CCPA_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="CCPA (California Consumer Privacy Act)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
