"""Argentina AI Governance compliance checks for AI agents.

This module defines the key requirements from Argentina's AI governance
landscape, covering Ley 25.326 AI extensions, Bill 3003-D-2024 (AI Regulation
Bill), AAIP (Agencia de Acceso a la Informacion Publica) guidance, and
provincial protocols.  It provides an evaluation function that maps security
findings and agent results to a :class:`~aisec.core.models.ComplianceChecklist`.

References:
- Ley 25.326: http://servicios.infoleg.gob.ar/infolegInternet/anexos/60000-64999/64790/norma.htm
- Bill 3003-D-2024: https://www.hcdn.gob.ar/proyectos/proyecto.jsp?exp=3003-D-2024
- AAIP: https://www.argentina.gob.ar/aaip
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
# Argentina AI Governance Compliance Checks
# ---------------------------------------------------------------------------

ARGENTINA_AI_CHECKS: list[dict[str, str]] = [
    # -----------------------------------------------------------------------
    # Ley 25.326 (Habeas Data - AI Extension)
    # -----------------------------------------------------------------------
    {
        "id": "ARGA-25326-AI.1",
        "article": "Ley 25.326 - AI Extension",
        "requirement": "Automated decision-making transparency",
        "description": (
            "When personal data is processed through automated "
            "decision-making systems, including AI agents, data subjects must "
            "be informed that automated processing is taking place, the logic "
            "involved, and the significance and envisaged consequences of "
            "such processing.  AI agent systems that make or support "
            "decisions affecting individuals must provide clear notification "
            "of automated processing and its potential impact."
        ),
    },
    {
        "id": "ARGA-25326-AI.2",
        "article": "Ley 25.326 - AI Extension",
        "requirement": "Right to explanation for AI-processed personal data",
        "description": (
            "Data subjects have the right to obtain a meaningful explanation "
            "of the logic, significance, and consequences when their personal "
            "data is processed by AI systems, extending the access rights "
            "under Ley 25.326.  AI agent systems must be capable of "
            "generating human-understandable explanations of how personal "
            "data influenced automated outcomes, including the key factors "
            "and data points considered in the decision."
        ),
    },
    {
        "id": "ARGA-25326-AI.3",
        "article": "Ley 25.326 - AI Extension",
        "requirement": "AI profiling restrictions",
        "description": (
            "Profiling of individuals through AI systems that produces legal "
            "or similarly significant effects must be subject to safeguards, "
            "including the right to obtain human intervention, to express "
            "their point of view, and to contest the decision.  AI agent "
            "systems that engage in profiling must implement mechanisms for "
            "human review and provide data subjects with effective channels "
            "to challenge profiling-based decisions."
        ),
    },
    # -----------------------------------------------------------------------
    # Bill 3003-D-2024 (AI Regulation Bill)
    # -----------------------------------------------------------------------
    {
        "id": "ARGA-3003.Art4",
        "article": "Bill 3003-D-2024, Art. 4",
        "requirement": "High-risk AI system identification",
        "description": (
            "AI systems shall be classified by risk level, with high-risk "
            "systems identified based on their potential impact on "
            "fundamental rights, health, safety, and democratic processes.  "
            "Sectors including healthcare, education, employment, law "
            "enforcement, and critical infrastructure are presumed high-risk.  "
            "AI agent deployments must undergo risk classification to "
            "determine whether they fall within the high-risk category and "
            "apply corresponding regulatory requirements."
        ),
    },
    {
        "id": "ARGA-3003.Art5",
        "article": "Bill 3003-D-2024, Art. 5",
        "requirement": "Mandatory impact assessment for high-risk AI",
        "description": (
            "High-risk AI systems must undergo a mandatory impact assessment "
            "prior to deployment, evaluating potential effects on fundamental "
            "rights, discrimination risks, safety implications, and societal "
            "consequences.  The assessment must be documented and made "
            "available to the supervisory authority upon request.  AI agent "
            "systems classified as high-risk must complete a comprehensive "
            "impact assessment covering bias, safety, privacy, and "
            "socioeconomic effects before production deployment."
        ),
    },
    {
        "id": "ARGA-3003.Art6",
        "article": "Bill 3003-D-2024, Art. 6",
        "requirement": "Traceability and auditability requirements",
        "description": (
            "AI systems must maintain sufficient logging and documentation "
            "to enable traceability of decisions and auditability of "
            "operations throughout the system life cycle.  Logs must include "
            "input data, model versions, decision outputs, and operational "
            "parameters.  AI agent systems must implement comprehensive "
            "audit trails that allow reconstruction of decision-making "
            "processes, including prompt inputs, model responses, tool "
            "invocations, and final outputs."
        ),
    },
    {
        "id": "ARGA-3003.Art7",
        "article": "Bill 3003-D-2024, Art. 7",
        "requirement": "Human oversight for public service AI",
        "description": (
            "AI systems deployed in public services must incorporate "
            "meaningful human oversight mechanisms, ensuring that a qualified "
            "human operator can understand, monitor, intervene in, and "
            "override the AI system's outputs.  Public sector AI agent "
            "deployments must implement human-in-the-loop or "
            "human-on-the-loop controls with documented escalation "
            "procedures and the ability to halt automated processing."
        ),
    },
    {
        "id": "ARGA-3003.Art8",
        "article": "Bill 3003-D-2024, Art. 8",
        "requirement": "Transparency and explainability obligations",
        "description": (
            "AI system operators must ensure transparency regarding the use "
            "of AI, including clear disclosure when users are interacting "
            "with an AI system, the general logic of the system, and the "
            "data categories used.  AI agent systems must clearly identify "
            "themselves as AI to users, provide accessible explanations of "
            "their capabilities and limitations, and disclose the types of "
            "data they process."
        ),
    },
    {
        "id": "ARGA-3003.Art9",
        "article": "Bill 3003-D-2024, Art. 9",
        "requirement": "Non-discrimination and fairness",
        "description": (
            "AI systems must be designed and operated to avoid "
            "discrimination based on race, gender, age, disability, "
            "socioeconomic status, geographic origin, or other protected "
            "characteristics.  Developers and operators must conduct bias "
            "assessments and implement mitigation measures.  AI agent "
            "systems must undergo fairness testing across protected groups, "
            "implement bias mitigation strategies, and maintain ongoing "
            "monitoring for discriminatory outcomes."
        ),
    },
    {
        "id": "ARGA-3003.Art10",
        "article": "Bill 3003-D-2024, Art. 10",
        "requirement": "Data protection alignment",
        "description": (
            "AI systems processing personal data must comply with existing "
            "data protection legislation, including Ley 25.326 and its "
            "regulatory provisions.  Data minimization, purpose limitation, "
            "and security requirements apply fully to AI processing.  AI "
            "agent systems must integrate data protection by design, "
            "ensuring that personal data processing adheres to lawfulness, "
            "purpose limitation, data minimisation, accuracy, and security "
            "principles established under Argentine data protection law."
        ),
    },
    # -----------------------------------------------------------------------
    # AAIP (Agencia de Acceso a la Informacion Publica) Guidance
    # -----------------------------------------------------------------------
    {
        "id": "ARGA-AAIP.1",
        "article": "AAIP Guidance",
        "requirement": "AI system registration requirements",
        "description": (
            "Organizations deploying AI systems that process personal data "
            "must register such systems with the AAIP, providing details on "
            "the type of AI technology used, the categories of personal data "
            "processed, the purpose of processing, and the security measures "
            "in place.  AI agent systems handling personal data must be "
            "included in the organization's data processing registry filed "
            "with the AAIP, with accurate descriptions of AI-specific "
            "processing activities."
        ),
    },
    {
        "id": "ARGA-AAIP.2",
        "article": "AAIP Guidance",
        "requirement": "Privacy impact assessment for AI",
        "description": (
            "Organizations must conduct privacy impact assessments for AI "
            "systems that process personal data at scale or that involve "
            "profiling, automated decision-making, or processing of "
            "sensitive data.  The assessment must identify privacy risks, "
            "evaluate their likelihood and severity, and define mitigation "
            "measures.  AI agent systems must undergo documented privacy "
            "impact assessments that specifically address AI-related risks "
            "such as inference of sensitive attributes, re-identification, "
            "and unintended data retention."
        ),
    },
    {
        "id": "ARGA-AAIP.3",
        "article": "AAIP Guidance",
        "requirement": "Cross-border data transfer for AI processing",
        "description": (
            "AI systems that transfer personal data to other jurisdictions "
            "for processing, training, or inference must comply with "
            "cross-border transfer requirements, including ensuring adequate "
            "protection levels or implementing appropriate safeguards such "
            "as contractual clauses.  AI agent systems using cloud-based "
            "models, external APIs, or foreign infrastructure must document "
            "all cross-border data flows and implement appropriate transfer "
            "mechanisms compliant with Argentine data protection law."
        ),
    },
    # -----------------------------------------------------------------------
    # Provincial Protocols
    # -----------------------------------------------------------------------
    {
        "id": "ARGA-PROV.1",
        "article": "Provincial Protocols (Buenos Aires, Santa Fe)",
        "requirement": "Facial recognition restrictions",
        "description": (
            "Several Argentine provinces, including Buenos Aires and Santa Fe, "
            "have enacted restrictions on the use of facial recognition "
            "technology in public spaces, requiring judicial authorization, "
            "proportionality assessments, and strict purpose limitation.  AI "
            "agent systems that incorporate facial recognition or biometric "
            "identification capabilities must comply with applicable "
            "provincial restrictions, obtain required authorizations, and "
            "implement safeguards against mass surveillance and misuse of "
            "biometric data."
        ),
    },
    {
        "id": "ARGA-PROV.2",
        "article": "Provincial Protocols",
        "requirement": "Public sector AI usage transparency",
        "description": (
            "Provincial governments require transparency in the use of AI "
            "systems by public sector entities, including public disclosure "
            "of AI systems in use, their purposes, the data they process, "
            "and their impact on citizens' rights.  AI agent systems deployed "
            "by or on behalf of provincial public sector organizations must "
            "be publicly documented, with accessible information about their "
            "function, data usage, and mechanisms for citizen feedback and "
            "complaints."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to Argentina AI checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "ARGA-25326-AI.1": [
        "automated decision", "automated processing", "decision-making transparency",
        "AI notification", "algorithmic transparency",
    ],
    "ARGA-25326-AI.2": [
        "right to explanation", "explainability", "algorithmic explanation",
        "decision explanation", "logic explanation", "meaningful explanation",
    ],
    "ARGA-25326-AI.3": [
        "profiling", "AI profiling", "human intervention",
        "contest decision", "automated profiling",
    ],
    "ARGA-3003.Art4": [
        "high-risk AI", "risk classification", "risk level",
        "critical infrastructure", "high-risk system",
    ],
    "ARGA-3003.Art5": [
        "impact assessment", "mandatory assessment", "fundamental rights",
        "deployment assessment", "risk assessment",
    ],
    "ARGA-3003.Art6": [
        "traceability", "auditability", "audit trail",
        "logging", "decision log", "audit log",
    ],
    "ARGA-3003.Art7": [
        "human oversight", "human-in-the-loop", "human intervention",
        "public service", "override", "escalation",
    ],
    "ARGA-3003.Art8": [
        "transparency", "explainability", "AI disclosure",
        "AI identification", "system capabilities",
    ],
    "ARGA-3003.Art9": [
        "non-discrimination", "fairness", "bias",
        "protected characteristics", "discriminatory", "bias assessment",
    ],
    "ARGA-3003.Art10": [
        "data protection", "data minimization", "purpose limitation",
        "personal data", "data security", "lawfulness",
    ],
    "ARGA-AAIP.1": [
        "system registration", "AAIP registration", "data registry",
        "processing registry", "database registration",
    ],
    "ARGA-AAIP.2": [
        "privacy impact assessment", "PIA", "privacy risk",
        "sensitive attributes", "re-identification",
    ],
    "ARGA-AAIP.3": [
        "cross-border transfer", "international transfer", "data transfer",
        "cloud processing", "foreign infrastructure", "data export",
    ],
    "ARGA-PROV.1": [
        "facial recognition", "biometric", "biometric identification",
        "mass surveillance", "facial detection",
    ],
    "ARGA-PROV.2": [
        "public sector transparency", "public disclosure", "government AI",
        "citizen rights", "public accountability", "public sector AI",
    ],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of Argentina AI check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_argentina_ai(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate Argentina AI Governance compliance based on findings.

    This function maps security findings to the relevant requirements from
    Argentina's AI governance landscape, including Ley 25.326 AI extensions,
    Bill 3003-D-2024, AAIP guidance, and provincial protocols, and produces
    a :class:`~aisec.core.models.ComplianceChecklist` that summarises the
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
        Argentina AI Governance.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in ARGENTINA_AI_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in ARGENTINA_AI_CHECKS:
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

    total = len(ARGENTINA_AI_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="Argentina AI Governance (Ley 25.326 AI Extension, Bill 3003-D-2024, AAIP, Provincial Protocols)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
