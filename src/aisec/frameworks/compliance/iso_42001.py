"""ISO/IEC 42001:2023 AI Management System compliance checks for AI agents.

This module defines the key clauses and controls of ISO/IEC 42001:2023
(Artificial Intelligence Management System) relevant to AI agent systems and
provides an evaluation function that maps security findings and agent results
to a :class:`~aisec.core.models.ComplianceChecklist`.

Reference: https://www.iso.org/standard/81230.html
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
# ISO/IEC 42001:2023 Compliance Checks
# ---------------------------------------------------------------------------

ISO_42001_CHECKS: list[dict[str, str]] = [
    # Clause 4 -- Context of the organization
    {
        "id": "ISO42001-4.1",
        "article": "Clause 4.1",
        "requirement": "Understanding the organization and its context",
        "description": (
            "The organization shall determine external and internal issues "
            "that are relevant to its purpose and that affect its ability to "
            "achieve the intended outcomes of its AI management system.  AI "
            "agent deployments must be evaluated within the broader "
            "organizational context, including industry sector, regulatory "
            "environment, and stakeholder expectations regarding AI use."
        ),
    },
    {
        "id": "ISO42001-4.2",
        "article": "Clause 4.2",
        "requirement": "Understanding the needs and expectations of interested parties",
        "description": (
            "The organization shall determine the interested parties that are "
            "relevant to the AI management system and their requirements, "
            "including regulatory bodies, customers, employees, and affected "
            "communities.  AI agent systems must account for the expectations "
            "and concerns of all stakeholders impacted by AI decisions."
        ),
    },
    {
        "id": "ISO42001-4.3",
        "article": "Clause 4.3",
        "requirement": "Determining the scope of the AI management system",
        "description": (
            "The organization shall determine the boundaries and applicability "
            "of the AI management system to establish its scope, considering "
            "the external and internal issues, requirements of interested "
            "parties, and organizational AI activities.  AI agent systems must "
            "be explicitly included or excluded from the AIMS scope with "
            "documented justification."
        ),
    },
    {
        "id": "ISO42001-4.4",
        "article": "Clause 4.4",
        "requirement": "AI management system",
        "description": (
            "The organization shall establish, implement, maintain, and "
            "continually improve an AI management system, including the "
            "processes needed and their interactions.  AI agent development, "
            "deployment, and operation must be governed by documented "
            "management system processes that are regularly reviewed."
        ),
    },
    # Clause 5 -- Leadership
    {
        "id": "ISO42001-5.1",
        "article": "Clause 5.1",
        "requirement": "Leadership and commitment",
        "description": (
            "Top management shall demonstrate leadership and commitment with "
            "respect to the AI management system by ensuring the AI policy "
            "and objectives are established, resources are available, and the "
            "importance of effective AI management is communicated.  AI agent "
            "governance must have visible executive sponsorship and "
            "accountability at the highest organizational level."
        ),
    },
    {
        "id": "ISO42001-5.2",
        "article": "Clause 5.2",
        "requirement": "AI policy",
        "description": (
            "Top management shall establish an AI policy that is appropriate "
            "to the purpose of the organization, provides a framework for "
            "setting AI objectives, includes a commitment to satisfy "
            "applicable requirements, and includes a commitment to continual "
            "improvement.  AI agent operations must be governed by a formal, "
            "documented AI policy that addresses responsible AI principles."
        ),
    },
    {
        "id": "ISO42001-5.3",
        "article": "Clause 5.3",
        "requirement": "Organizational roles, responsibilities, and authorities",
        "description": (
            "Top management shall ensure that responsibilities and authorities "
            "for relevant roles are assigned and communicated within the "
            "organization.  AI agent systems must have clearly defined roles "
            "including AI system owner, data steward, model validator, and "
            "ethical review authority with documented accountability."
        ),
    },
    # Clause 6 -- Planning
    {
        "id": "ISO42001-6.1",
        "article": "Clause 6.1",
        "requirement": "Actions to address risks and opportunities",
        "description": (
            "The organization shall determine risks and opportunities that "
            "need to be addressed to ensure the AI management system can "
            "achieve its intended outcomes, prevent or reduce undesired "
            "effects, and achieve continual improvement.  AI agent risk "
            "assessments must be conducted systematically, covering technical, "
            "ethical, legal, and societal dimensions."
        ),
    },
    {
        "id": "ISO42001-6.2",
        "article": "Clause 6.2",
        "requirement": "AI objectives and planning to achieve them",
        "description": (
            "The organization shall establish AI objectives at relevant "
            "functions, levels, and processes that are consistent with the "
            "AI policy, measurable, monitored, communicated, and updated as "
            "appropriate.  AI agent deployments must have defined, measurable "
            "objectives for performance, fairness, safety, and transparency."
        ),
    },
    {
        "id": "ISO42001-6.3",
        "article": "Clause 6.3",
        "requirement": "Planning of changes",
        "description": (
            "When the organization determines the need for changes to the AI "
            "management system, the changes shall be carried out in a planned "
            "manner, considering the purpose of the changes, potential "
            "consequences, integrity of the management system, and resource "
            "availability.  AI agent updates, retraining, and configuration "
            "changes must follow formal change management procedures."
        ),
    },
    # Clause 7 -- Support
    {
        "id": "ISO42001-7.1",
        "article": "Clause 7.1",
        "requirement": "Resources",
        "description": (
            "The organization shall determine and provide the resources needed "
            "for the establishment, implementation, maintenance, and continual "
            "improvement of the AI management system, including human "
            "resources, infrastructure, and technology.  AI agent systems must "
            "have adequate computational resources, skilled personnel, and "
            "supporting infrastructure documented and maintained."
        ),
    },
    {
        "id": "ISO42001-7.2",
        "article": "Clause 7.2",
        "requirement": "Competence",
        "description": (
            "The organization shall determine the necessary competence of "
            "persons doing work that affects AI management system performance, "
            "ensure they are competent on the basis of education, training, "
            "or experience, and retain documented evidence of competence.  "
            "Teams developing and operating AI agents must have demonstrable "
            "competence in AI/ML, security, ethics, and domain expertise."
        ),
    },
    {
        "id": "ISO42001-7.3",
        "article": "Clause 7.3",
        "requirement": "Awareness",
        "description": (
            "Persons doing work under the organization's control shall be "
            "aware of the AI policy, their contribution to the effectiveness "
            "of the AI management system, and the implications of not "
            "conforming.  All personnel interacting with AI agent systems "
            "must receive awareness training on responsible AI use, risks, "
            "and organizational AI policies."
        ),
    },
    {
        "id": "ISO42001-7.4",
        "article": "Clause 7.4",
        "requirement": "Communication",
        "description": (
            "The organization shall determine the internal and external "
            "communications relevant to the AI management system, including "
            "what, when, with whom, and how to communicate.  AI agent "
            "incident reports, performance metrics, and risk assessments "
            "must be communicated to relevant stakeholders through defined "
            "channels and frequencies."
        ),
    },
    {
        "id": "ISO42001-7.5",
        "article": "Clause 7.5",
        "requirement": "Documented information",
        "description": (
            "The AI management system shall include documented information "
            "required by the standard and determined by the organization as "
            "necessary for effectiveness.  AI agent systems must maintain "
            "comprehensive documentation including model cards, data sheets, "
            "risk assessments, test results, deployment records, and "
            "operational procedures."
        ),
    },
    # Clause 8 -- Operation
    {
        "id": "ISO42001-8.1",
        "article": "Clause 8.1",
        "requirement": "Operational planning and control",
        "description": (
            "The organization shall plan, implement, and control the "
            "processes needed to meet requirements and implement the actions "
            "determined in planning, by establishing criteria for the "
            "processes and implementing control of the processes in accordance "
            "with the criteria.  AI agent development and deployment must "
            "follow documented operational procedures with defined quality "
            "gates and approval processes."
        ),
    },
    {
        "id": "ISO42001-8.2",
        "article": "Clause 8.2",
        "requirement": "AI system impact assessment",
        "description": (
            "The organization shall conduct an AI system impact assessment "
            "to identify and evaluate the potential impacts of AI systems on "
            "individuals, groups, and society, considering both intended and "
            "unintended consequences.  AI agent deployments must undergo "
            "formal impact assessment before production use, covering bias, "
            "safety, privacy, and societal effects."
        ),
    },
    {
        "id": "ISO42001-8.3",
        "article": "Clause 8.3",
        "requirement": "AI system life cycle processes",
        "description": (
            "The organization shall establish and implement processes for the "
            "AI system life cycle, including design, development, testing, "
            "deployment, operation, and decommissioning.  AI agent systems "
            "must have defined life cycle management covering versioning, "
            "testing protocols, staged rollout, monitoring, and end-of-life "
            "procedures."
        ),
    },
    {
        "id": "ISO42001-8.4",
        "article": "Clause 8.4",
        "requirement": "Data for AI systems and third-party considerations",
        "description": (
            "The organization shall manage data used by AI systems throughout "
            "its life cycle, ensuring data quality, provenance, and "
            "appropriate handling, and shall manage risks related to "
            "third-party AI components.  AI agent data pipelines must have "
            "documented data governance, quality checks, provenance tracking, "
            "and third-party component risk assessments."
        ),
    },
    # Clause 9 -- Performance evaluation
    {
        "id": "ISO42001-9.1",
        "article": "Clause 9.1",
        "requirement": "Monitoring, measurement, analysis, and evaluation",
        "description": (
            "The organization shall determine what needs to be monitored and "
            "measured, the methods for monitoring and measurement, when "
            "monitoring and measuring shall be performed, and when results "
            "shall be analysed and evaluated.  AI agent systems must have "
            "continuous monitoring for performance degradation, drift, bias, "
            "security incidents, and compliance deviations."
        ),
    },
    {
        "id": "ISO42001-9.2",
        "article": "Clause 9.2",
        "requirement": "Internal audit",
        "description": (
            "The organization shall conduct internal audits at planned "
            "intervals to provide information on whether the AI management "
            "system conforms to the organization's own requirements and to "
            "the requirements of the standard.  AI agent systems must be "
            "subject to periodic internal audits covering technical controls, "
            "process compliance, and ethical alignment."
        ),
    },
    {
        "id": "ISO42001-9.3",
        "article": "Clause 9.3",
        "requirement": "Management review",
        "description": (
            "Top management shall review the organization's AI management "
            "system at planned intervals to ensure its continuing suitability, "
            "adequacy, effectiveness, and alignment with the strategic "
            "direction of the organization.  AI agent governance must include "
            "scheduled management reviews with documented decisions and "
            "actions arising from the review."
        ),
    },
    # Clause 10 -- Improvement
    {
        "id": "ISO42001-10.1",
        "article": "Clause 10.1",
        "requirement": "Nonconformity and corrective action",
        "description": (
            "When a nonconformity occurs, the organization shall react to the "
            "nonconformity, evaluate the need for action to eliminate the "
            "causes, implement any action needed, review the effectiveness of "
            "corrective action, and make changes to the AI management system "
            "if necessary.  AI agent incidents, failures, and compliance "
            "breaches must trigger formal nonconformity handling with root "
            "cause analysis and corrective actions."
        ),
    },
    {
        "id": "ISO42001-10.2",
        "article": "Clause 10.2",
        "requirement": "Continual improvement",
        "description": (
            "The organization shall continually improve the suitability, "
            "adequacy, and effectiveness of the AI management system.  AI "
            "agent systems must be subject to ongoing improvement processes "
            "informed by monitoring data, audit findings, management reviews, "
            "incident analysis, and evolving best practices in responsible AI."
        ),
    },
    # Annex A -- AI Controls
    {
        "id": "ISO42001-A.2",
        "article": "Annex A.2",
        "requirement": "AI impact assessment",
        "description": (
            "The organization shall conduct AI impact assessments to identify "
            "and evaluate the potential effects of AI systems on individuals, "
            "groups, societies, and ecosystems, covering human rights, "
            "fairness, transparency, accountability, and safety.  AI agent "
            "deployments must have documented impact assessments that consider "
            "direct and indirect effects on all affected stakeholders."
        ),
    },
    {
        "id": "ISO42001-A.3",
        "article": "Annex A.3",
        "requirement": "AI system life cycle",
        "description": (
            "The organization shall manage AI systems throughout their life "
            "cycle, including requirements analysis, design, development, "
            "verification, validation, deployment, operation, and retirement.  "
            "AI agent life cycle management must include formal stage gates, "
            "validation criteria, deployment checklists, operational "
            "monitoring, and decommissioning procedures."
        ),
    },
    {
        "id": "ISO42001-A.4",
        "article": "Annex A.4",
        "requirement": "Data for AI systems",
        "description": (
            "The organization shall establish processes for data management "
            "throughout the AI system life cycle, including data collection, "
            "labelling, quality assurance, storage, access control, and "
            "disposition.  AI agent training data, operational data, and "
            "output data must have documented governance covering provenance, "
            "quality metrics, bias assessment, and retention policies."
        ),
    },
    {
        "id": "ISO42001-A.10",
        "article": "Annex A.10",
        "requirement": "Third-party and customer relationships",
        "description": (
            "The organization shall manage risks related to third-party AI "
            "components, services, and customer use of AI systems, including "
            "supply chain transparency, contractual requirements, and "
            "monitoring of third-party performance.  AI agent systems using "
            "external models, APIs, data sources, or libraries must have "
            "documented supplier assessments, contractual safeguards, and "
            "ongoing monitoring of third-party risks."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to ISO 42001 checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "ISO42001-4.1": [
        "organizational context", "external issues", "internal issues",
        "operating environment", "regulatory environment",
    ],
    "ISO42001-4.2": [
        "interested parties", "stakeholder", "stakeholder expectations",
        "regulatory requirements", "customer requirements",
    ],
    "ISO42001-4.3": [
        "scope", "management system scope", "AIMS scope",
        "system boundaries", "applicability",
    ],
    "ISO42001-4.4": [
        "management system", "AIMS", "process interactions",
        "system establishment", "continual improvement",
    ],
    "ISO42001-5.1": [
        "leadership", "top management", "executive commitment",
        "governance", "accountability",
    ],
    "ISO42001-5.2": [
        "AI policy", "responsible AI", "AI principles",
        "ethical AI", "policy framework",
    ],
    "ISO42001-5.3": [
        "roles and responsibilities", "authority", "organizational roles",
        "AI system owner", "data steward", "model validator",
    ],
    "ISO42001-6.1": [
        "risk assessment", "risk management", "opportunity",
        "risk treatment", "AI risk", "threat assessment",
    ],
    "ISO42001-6.2": [
        "AI objectives", "measurable objectives", "performance targets",
        "fairness objectives", "safety objectives",
    ],
    "ISO42001-6.3": [
        "change management", "planned changes", "configuration change",
        "model update", "retraining", "version control",
    ],
    "ISO42001-7.1": [
        "resources", "infrastructure", "computational resources",
        "human resources", "budget", "capacity",
    ],
    "ISO42001-7.2": [
        "competence", "training", "education", "skills",
        "expertise", "qualification",
    ],
    "ISO42001-7.3": [
        "awareness", "awareness training", "AI literacy",
        "responsible use", "staff awareness",
    ],
    "ISO42001-7.4": [
        "communication", "incident reporting", "stakeholder communication",
        "notification", "disclosure",
    ],
    "ISO42001-7.5": [
        "documentation", "documented information", "model card",
        "data sheet", "records", "record keeping",
    ],
    "ISO42001-8.1": [
        "operational planning", "operational control", "quality gate",
        "approval process", "deployment procedure",
    ],
    "ISO42001-8.2": [
        "impact assessment", "AI impact", "societal impact",
        "bias assessment", "safety assessment", "ethical impact",
    ],
    "ISO42001-8.3": [
        "life cycle", "system development", "design and development",
        "testing", "deployment", "decommissioning", "versioning",
    ],
    "ISO42001-8.4": [
        "data management", "data quality", "data provenance",
        "data governance", "third-party component", "supply chain",
    ],
    "ISO42001-9.1": [
        "monitoring", "measurement", "performance evaluation",
        "drift detection", "model monitoring", "KPI",
    ],
    "ISO42001-9.2": [
        "internal audit", "audit", "compliance audit",
        "audit programme", "audit findings",
    ],
    "ISO42001-9.3": [
        "management review", "executive review", "governance review",
        "strategic review", "suitability review",
    ],
    "ISO42001-10.1": [
        "nonconformity", "corrective action", "root cause",
        "incident handling", "non-compliance", "remediation",
    ],
    "ISO42001-10.2": [
        "continual improvement", "continuous improvement",
        "improvement plan", "lessons learned", "best practices",
    ],
    "ISO42001-A.2": [
        "AI impact assessment", "human rights impact", "fairness impact",
        "societal assessment", "ethical assessment",
    ],
    "ISO42001-A.3": [
        "AI life cycle", "system life cycle", "development life cycle",
        "stage gate", "validation criteria", "retirement",
    ],
    "ISO42001-A.4": [
        "training data", "data labelling", "data collection",
        "data bias", "data retention", "data disposition",
    ],
    "ISO42001-A.10": [
        "third-party", "supplier", "vendor", "external model",
        "external API", "supply chain risk", "contractual",
    ],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of ISO 42001 check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_iso_42001(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate ISO/IEC 42001:2023 compliance based on findings and agent results.

    This function maps security findings to the relevant clauses and controls
    of ISO/IEC 42001:2023 and produces a
    :class:`~aisec.core.models.ComplianceChecklist` that summarises the
    compliance posture.

    The evaluation logic:
    - A check **fails** if any finding with severity >= HIGH is matched.
    - A check is **partial** if findings with severity < HIGH are matched.
    - A check **passes** if no findings are matched (indicating no detected
      violations, though this is not a guarantee of compliance).

    Args:
        findings: All security findings from the scan.
        agent_results: Results from individual security agents.

    Returns:
        A populated :class:`~aisec.core.models.ComplianceChecklist` for
        ISO/IEC 42001:2023.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in ISO_42001_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in ISO_42001_CHECKS:
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

    total = len(ISO_42001_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="ISO/IEC 42001:2023 (AI Management System)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
