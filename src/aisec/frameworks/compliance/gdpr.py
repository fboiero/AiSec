"""GDPR (General Data Protection Regulation) compliance checks for AI agents.

This module defines the key GDPR articles relevant to AI agent systems and
provides an evaluation function that maps security findings and agent results
to a :class:`~aisec.core.models.ComplianceChecklist`.

Reference: https://gdpr-info.eu/
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
# GDPR Compliance Checks
# ---------------------------------------------------------------------------

GDPR_CHECKS: list[dict[str, str]] = [
    # Article 5 -- Principles relating to processing of personal data
    {
        "id": "GDPR-Art5.1.a",
        "article": "Art. 5(1)(a)",
        "requirement": "Lawfulness, fairness, and transparency",
        "description": (
            "Personal data must be processed lawfully, fairly, and in a "
            "transparent manner in relation to the data subject.  AI agents "
            "must not process personal data without a valid legal basis, and "
            "their data handling practices must be explainable."
        ),
    },
    {
        "id": "GDPR-Art5.1.b",
        "article": "Art. 5(1)(b)",
        "requirement": "Purpose limitation",
        "description": (
            "Personal data must be collected for specified, explicit, and "
            "legitimate purposes and not further processed in a manner "
            "incompatible with those purposes.  AI agents must not repurpose "
            "personal data beyond the original collection intent."
        ),
    },
    {
        "id": "GDPR-Art5.1.c",
        "article": "Art. 5(1)(c)",
        "requirement": "Data minimisation",
        "description": (
            "Personal data must be adequate, relevant, and limited to what is "
            "necessary in relation to the purposes for which it is processed.  "
            "AI agents should minimise the personal data they access and retain."
        ),
    },
    {
        "id": "GDPR-Art5.1.d",
        "article": "Art. 5(1)(d)",
        "requirement": "Accuracy",
        "description": (
            "Personal data must be accurate and, where necessary, kept up to "
            "date.  AI agents must not generate or propagate inaccurate "
            "personal data."
        ),
    },
    {
        "id": "GDPR-Art5.1.e",
        "article": "Art. 5(1)(e)",
        "requirement": "Storage limitation",
        "description": (
            "Personal data must be kept in a form that permits identification "
            "of data subjects for no longer than necessary.  AI agent memory "
            "and logs containing personal data must have defined retention "
            "periods."
        ),
    },
    {
        "id": "GDPR-Art5.1.f",
        "article": "Art. 5(1)(f)",
        "requirement": "Integrity and confidentiality",
        "description": (
            "Personal data must be processed in a manner that ensures "
            "appropriate security, including protection against unauthorised "
            "or unlawful processing and against accidental loss, destruction, "
            "or damage."
        ),
    },
    # Article 6 -- Lawfulness of processing
    {
        "id": "GDPR-Art6",
        "article": "Art. 6",
        "requirement": "Lawful basis for processing",
        "description": (
            "Processing is lawful only if at least one of the specified legal "
            "bases applies (consent, contract, legal obligation, vital "
            "interests, public task, or legitimate interests).  AI agent data "
            "processing must be mapped to an explicit legal basis."
        ),
    },
    # Article 7 -- Conditions for consent
    {
        "id": "GDPR-Art7",
        "article": "Art. 7",
        "requirement": "Conditions for valid consent",
        "description": (
            "Where processing is based on consent, the controller must be able "
            "to demonstrate that the data subject has consented.  Consent must "
            "be freely given, specific, informed, and unambiguous.  AI agents "
            "must not process data beyond the scope of given consent."
        ),
    },
    # Articles 13-14 -- Transparency obligations
    {
        "id": "GDPR-Art13",
        "article": "Art. 13",
        "requirement": "Information to be provided when data is collected from the data subject",
        "description": (
            "At the time of data collection, data subjects must be informed "
            "about the controller's identity, processing purposes, legal basis, "
            "recipients, retention periods, and their rights.  AI agent "
            "interactions must include appropriate privacy notices."
        ),
    },
    {
        "id": "GDPR-Art14",
        "article": "Art. 14",
        "requirement": "Information when data is not obtained from the data subject",
        "description": (
            "When personal data is obtained from sources other than the data "
            "subject, the controller must provide the same transparency "
            "information within a reasonable period.  AI agents ingesting "
            "third-party data must comply with this obligation."
        ),
    },
    # Article 15 -- Right of access
    {
        "id": "GDPR-Art15",
        "article": "Art. 15",
        "requirement": "Right of access by the data subject",
        "description": (
            "Data subjects have the right to obtain confirmation of whether "
            "their personal data is being processed and, if so, access to that "
            "data and supplementary information.  Systems using AI agents must "
            "support data subject access requests."
        ),
    },
    # Article 17 -- Right to erasure
    {
        "id": "GDPR-Art17",
        "article": "Art. 17",
        "requirement": "Right to erasure (right to be forgotten)",
        "description": (
            "Data subjects have the right to obtain erasure of their personal "
            "data without undue delay under specified conditions.  AI agent "
            "memory stores, logs, and cached data must support erasure "
            "operations."
        ),
    },
    # Article 20 -- Right to data portability
    {
        "id": "GDPR-Art20",
        "article": "Art. 20",
        "requirement": "Right to data portability",
        "description": (
            "Data subjects have the right to receive their personal data in a "
            "structured, commonly used, and machine-readable format.  AI agent "
            "systems must be able to export personal data in portable formats."
        ),
    },
    # Article 25 -- Data protection by design and by default
    {
        "id": "GDPR-Art25",
        "article": "Art. 25",
        "requirement": "Data protection by design and by default",
        "description": (
            "The controller must implement appropriate technical and "
            "organisational measures designed to implement data protection "
            "principles effectively.  AI agents must be designed with privacy "
            "safeguards from the outset, not bolted on after deployment."
        ),
    },
    # Article 32 -- Security of processing
    {
        "id": "GDPR-Art32",
        "article": "Art. 32",
        "requirement": "Security of processing",
        "description": (
            "Controllers and processors must implement appropriate technical "
            "and organisational measures to ensure a level of security "
            "appropriate to the risk, including encryption, pseudonymisation, "
            "resilience, and regular testing.  AI agent infrastructure must "
            "meet these security requirements."
        ),
    },
    # Articles 33-34 -- Breach notification
    {
        "id": "GDPR-Art33",
        "article": "Art. 33",
        "requirement": "Notification of a personal data breach to the supervisory authority",
        "description": (
            "In the case of a personal data breach, the controller must notify "
            "the supervisory authority within 72 hours.  AI agent systems must "
            "have breach detection and notification capabilities."
        ),
    },
    {
        "id": "GDPR-Art34",
        "article": "Art. 34",
        "requirement": "Communication of a personal data breach to the data subject",
        "description": (
            "When a breach is likely to result in a high risk to the rights "
            "and freedoms of natural persons, the controller must communicate "
            "the breach to the affected data subjects.  AI agent breach "
            "response plans must include subject notification procedures."
        ),
    },
    # Article 35 -- Data protection impact assessment
    {
        "id": "GDPR-Art35",
        "article": "Art. 35",
        "requirement": "Data Protection Impact Assessment (DPIA)",
        "description": (
            "Where processing is likely to result in a high risk to the rights "
            "and freedoms of natural persons, the controller must carry out a "
            "DPIA.  AI agent deployments processing personal data at scale or "
            "involving automated decision-making require a DPIA."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to GDPR checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "GDPR-Art5.1.a": ["lawfulness", "fairness", "transparency", "legal basis"],
    "GDPR-Art5.1.b": ["purpose limitation", "repurpose", "secondary use"],
    "GDPR-Art5.1.c": ["data minimisation", "excessive data", "unnecessary data"],
    "GDPR-Art5.1.d": ["accuracy", "inaccurate", "outdated data"],
    "GDPR-Art5.1.e": ["storage limitation", "retention", "data retention"],
    "GDPR-Art5.1.f": [
        "integrity", "confidentiality", "unauthorised access",
        "data breach", "encryption",
    ],
    "GDPR-Art6": ["legal basis", "consent", "legitimate interest", "lawful"],
    "GDPR-Art7": ["consent", "opt-in", "withdraw consent"],
    "GDPR-Art13": ["privacy notice", "transparency", "information provision"],
    "GDPR-Art14": ["third-party data", "indirect collection"],
    "GDPR-Art15": ["access request", "right of access", "data access"],
    "GDPR-Art17": ["erasure", "deletion", "right to be forgotten"],
    "GDPR-Art20": ["portability", "data export", "machine-readable"],
    "GDPR-Art25": [
        "privacy by design", "data protection by design", "default settings",
    ],
    "GDPR-Art32": [
        "security measures", "encryption", "pseudonymisation", "resilience",
        "security testing",
    ],
    "GDPR-Art33": ["breach notification", "supervisory authority", "72 hours"],
    "GDPR-Art34": ["breach communication", "data subject notification"],
    "GDPR-Art35": ["impact assessment", "DPIA", "high risk processing"],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of GDPR check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_gdpr(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate GDPR compliance based on security findings and agent results.

    This function maps security findings to the relevant GDPR articles and
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
        A populated :class:`~aisec.core.models.ComplianceChecklist` for GDPR.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in GDPR_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in GDPR_CHECKS:
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

    total = len(GDPR_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="GDPR (General Data Protection Regulation)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
