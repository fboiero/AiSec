"""EU AI Act compliance checks for AI agents.

This module defines the key EU AI Act articles relevant to AI agent systems and
provides an evaluation function that maps security findings and agent results
to a :class:`~aisec.core.models.ComplianceChecklist`.

The EU AI Act (Regulation (EU) 2024/1689) establishes a comprehensive
regulatory framework for artificial intelligence systems in the European Union,
introducing a risk-based approach that classifies AI systems according to the
level of risk they pose to health, safety, and fundamental rights.

Reference: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
"""

from __future__ import annotations

from typing import Any

from aisec.core.enums import CheckStatus, Severity
from aisec.core.models import (
    AgentResult,
    ComplianceCheckItem,
    ComplianceChecklist,
    Finding,
)


# ---------------------------------------------------------------------------
# EU AI Act Compliance Checks
# ---------------------------------------------------------------------------

EU_AI_ACT_CHECKS: list[dict[str, str]] = [
    # Article 6 -- Risk Classification
    {
        "id": "EUAIA-Art6",
        "article": "Art. 6",
        "requirement": "AI system risk classification",
        "description": (
            "AI systems must be classified according to the risk they pose: "
            "prohibited (unacceptable risk), high-risk, limited risk, or "
            "minimal risk.  AI agents must undergo a thorough risk "
            "classification assessment to determine the applicable regulatory "
            "obligations.  High-risk classification triggers extensive "
            "requirements under Articles 8-15, including risk management, "
            "data governance, transparency, and human oversight."
        ),
    },
    # Article 5 -- Prohibited AI Practices
    {
        "id": "EUAIA-Art5.1.a",
        "article": "Art. 5(1)(a)",
        "requirement": "Prohibition of social scoring by public authorities",
        "description": (
            "AI systems that evaluate or classify natural persons or groups "
            "based on their social behaviour or personal characteristics, "
            "leading to detrimental or unfavourable treatment (social "
            "scoring), are prohibited when deployed by or on behalf of public "
            "authorities.  AI agents must not implement, facilitate, or "
            "contribute to social scoring mechanisms that assess "
            "trustworthiness based on social behaviour, socio-economic "
            "status, or personal traits, particularly when the resulting "
            "score leads to exclusion from services or unjustified "
            "restrictions of rights."
        ),
    },
    {
        "id": "EUAIA-Art5.1.b",
        "article": "Art. 5(1)(b)",
        "requirement": "Prohibition of exploitation of vulnerabilities",
        "description": (
            "AI systems that exploit vulnerabilities of specific groups of "
            "persons due to their age, disability, or specific social or "
            "economic situation, with the objective or effect of materially "
            "distorting their behaviour in a manner that causes or is likely "
            "to cause significant harm, are prohibited.  AI agents must not "
            "target or exploit individuals who are vulnerable due to age "
            "(such as children or the elderly), physical or mental "
            "disability, or socio-economic disadvantage in ways that could "
            "manipulate their decisions or cause them harm."
        ),
    },
    {
        "id": "EUAIA-Art5.1.c",
        "article": "Art. 5(1)(c)",
        "requirement": "Prohibition of biometric categorization based on sensitive attributes",
        "description": (
            "AI systems that perform biometric categorization to infer "
            "sensitive attributes such as race, political opinions, trade "
            "union membership, religious or philosophical beliefs, sex life, "
            "or sexual orientation are prohibited, except for lawful labelling "
            "or filtering of biometric datasets or when law enforcement "
            "categorises biometric data.  AI agents must not process "
            "biometric data to classify individuals according to these "
            "protected characteristics."
        ),
    },
    {
        "id": "EUAIA-Art5.1.d",
        "article": "Art. 5(1)(d)",
        "requirement": "Prohibition of real-time remote biometric identification in public spaces",
        "description": (
            "The use of real-time remote biometric identification systems in "
            "publicly accessible spaces for the purpose of law enforcement is "
            "prohibited, subject to narrow exceptions (e.g., targeted search "
            "for specific crime victims, prevention of imminent threats, "
            "identification of suspects of serious crimes).  AI agents must "
            "not perform or enable real-time remote biometric identification "
            "of individuals in public spaces unless operating under an "
            "explicit legal exception with appropriate safeguards and prior "
            "judicial authorization."
        ),
    },
    # Articles 8-15 -- High-Risk AI System Requirements
    {
        "id": "EUAIA-Art9",
        "article": "Art. 9",
        "requirement": "Risk management system",
        "description": (
            "High-risk AI systems must establish, implement, document, and "
            "maintain a risk management system throughout the entire "
            "lifecycle.  This system must identify and analyse known and "
            "reasonably foreseeable risks, estimate and evaluate risks that "
            "may emerge during use, adopt appropriate risk management "
            "measures, and ensure residual risks are acceptable.  AI agents "
            "classified as high-risk must have a continuously updated risk "
            "management framework that addresses risks from intended use, "
            "reasonably foreseeable misuse, and interaction with other "
            "systems."
        ),
    },
    {
        "id": "EUAIA-Art10",
        "article": "Art. 10",
        "requirement": "Data and data governance",
        "description": (
            "High-risk AI systems that use data for training must be "
            "developed on the basis of training, validation, and testing "
            "datasets that meet quality criteria.  Data governance and "
            "management practices must address data collection design, data "
            "preparation, relevant assumptions, prior assessment of data "
            "availability and suitability, examination for biases, and "
            "identification of data gaps.  AI agents must ensure that their "
            "training data and any data processed during operation meet these "
            "governance standards, with particular attention to avoiding bias "
            "and ensuring representativeness."
        ),
    },
    {
        "id": "EUAIA-Art11",
        "article": "Art. 11",
        "requirement": "Technical documentation",
        "description": (
            "Technical documentation of a high-risk AI system must be drawn "
            "up before that system is placed on the market or put into "
            "service.  The documentation must demonstrate compliance with "
            "high-risk requirements, provide national competent authorities "
            "and notified bodies with the information needed to assess "
            "compliance, and include a general description of the AI system, "
            "its intended purpose, design specifications, development "
            "methodology, monitoring and control mechanisms, and risk "
            "management measures.  AI agents must maintain comprehensive "
            "technical documentation that covers architecture, training "
            "processes, validation results, and operational parameters."
        ),
    },
    {
        "id": "EUAIA-Art12",
        "article": "Art. 12",
        "requirement": "Record-keeping and logging",
        "description": (
            "High-risk AI systems must be designed and developed with "
            "capabilities enabling the automatic recording of events "
            "(logging) throughout the system's lifetime.  Logging must "
            "ensure a level of traceability appropriate to the intended "
            "purpose, enabling monitoring of operation, identification of "
            "risks, and facilitating post-market monitoring.  AI agents must "
            "implement comprehensive logging that records operational "
            "decisions, data accesses, tool invocations, inter-agent "
            "communications, and any actions that affect individuals or "
            "groups."
        ),
    },
    {
        "id": "EUAIA-Art13",
        "article": "Art. 13",
        "requirement": "Transparency and information to deployers",
        "description": (
            "High-risk AI systems must be designed and developed to ensure "
            "that their operation is sufficiently transparent to enable "
            "deployers to interpret outputs and use them appropriately.  "
            "Instructions for use must include the provider's identity, "
            "system characteristics, capabilities and limitations, intended "
            "purpose, level of accuracy and robustness, known or foreseeable "
            "circumstances that may lead to risks, input data specifications, "
            "and human oversight measures.  AI agents must provide clear "
            "documentation enabling deployers to understand system behaviour, "
            "interpret outputs, and identify when human intervention is "
            "needed."
        ),
    },
    {
        "id": "EUAIA-Art14",
        "article": "Art. 14",
        "requirement": "Human oversight measures",
        "description": (
            "High-risk AI systems must be designed and developed so that they "
            "can be effectively overseen by natural persons during their "
            "period of use.  Human oversight must aim to prevent or minimise "
            "risks to health, safety, or fundamental rights.  Oversight "
            "measures must enable the individual to fully understand the "
            "system's capabilities and limitations, monitor operation, "
            "interpret outputs correctly, decide not to use or override "
            "outputs, and intervene or interrupt the system.  AI agents must "
            "incorporate mechanisms for meaningful human oversight, including "
            "the ability for human operators to override, interrupt, or "
            "shut down the agent at any time."
        ),
    },
    {
        "id": "EUAIA-Art15",
        "article": "Art. 15",
        "requirement": "Accuracy, robustness, and cybersecurity",
        "description": (
            "High-risk AI systems must be designed and developed to achieve "
            "an appropriate level of accuracy, robustness, and cybersecurity "
            "and perform consistently in those respects throughout their "
            "lifecycle.  Systems must be resilient to errors, faults, "
            "inconsistencies, and adversarial attacks (including data "
            "poisoning, model manipulation, and adversarial inputs).  AI "
            "agents must implement cybersecurity safeguards proportionate to "
            "the risks, including protection against prompt injection, data "
            "poisoning, model extraction, and other AI-specific attack "
            "vectors."
        ),
    },
    # Articles 52-55 -- GPAI (General-Purpose AI) Model Obligations
    {
        "id": "EUAIA-Art53",
        "article": "Art. 53",
        "requirement": "Obligations for GPAI model providers",
        "description": (
            "Providers of general-purpose AI models must draw up and keep "
            "up-to-date the technical documentation of the model, including "
            "its training and testing processes and evaluation results; "
            "prepare and keep up-to-date information and documentation for "
            "providers of AI systems that intend to integrate the GPAI model; "
            "establish a policy to comply with Union copyright law; and draw "
            "up and make publicly available a sufficiently detailed summary "
            "about the content used for training the model.  AI agents built "
            "on general-purpose AI models must ensure their foundation model "
            "providers satisfy these documentation, copyright, and "
            "transparency obligations."
        ),
    },
    {
        "id": "EUAIA-Art55",
        "article": "Art. 55",
        "requirement": "Systemic risk assessment for GPAI models",
        "description": (
            "Providers of general-purpose AI models with systemic risk must "
            "perform model evaluations, including adversarial testing, to "
            "identify and mitigate systemic risks; assess and mitigate "
            "possible systemic risks at Union level; track, document, and "
            "report serious incidents and possible corrective measures to the "
            "AI Office and national competent authorities; and ensure an "
            "adequate level of cybersecurity protection.  AI agents powered "
            "by GPAI models classified as posing systemic risk must undergo "
            "rigorous adversarial testing and maintain continuous risk "
            "monitoring and incident reporting processes."
        ),
    },
    # Article 50 -- Transparency Obligations
    {
        "id": "EUAIA-Art50.1",
        "article": "Art. 50(1)",
        "requirement": "AI system disclosure to users",
        "description": (
            "Providers must ensure that AI systems intended to interact "
            "directly with natural persons are designed and developed in such "
            "a way that the natural persons concerned are informed that they "
            "are interacting with an AI system, unless this is obvious from "
            "the circumstances and context of use.  AI agents that "
            "communicate with end users must clearly disclose their AI "
            "nature at the point of interaction, ensuring users are aware "
            "they are not communicating with a human."
        ),
    },
    {
        "id": "EUAIA-Art50.2",
        "article": "Art. 50(2)",
        "requirement": "Emotion recognition and biometric categorization disclosure",
        "description": (
            "Providers of AI systems that perform emotion recognition or "
            "biometric categorization must inform the natural persons exposed "
            "to the system about its operation and process personal data in "
            "accordance with applicable Union law.  AI agents that analyse "
            "user emotions, sentiment, or biometric characteristics must "
            "disclose this capability to affected individuals and ensure "
            "lawful processing of the associated personal data."
        ),
    },
    {
        "id": "EUAIA-Art50.3",
        "article": "Art. 50(3)",
        "requirement": "Deep fake disclosure",
        "description": (
            "Users of AI systems that generate or manipulate image, audio, or "
            "video content constituting a deep fake must disclose that the "
            "content has been artificially generated or manipulated.  AI "
            "agents that produce synthetic media, alter existing content, or "
            "generate realistic but artificial representations of people, "
            "events, or environments must label such outputs as "
            "AI-generated and ensure recipients are informed of their "
            "synthetic nature."
        ),
    },
    {
        "id": "EUAIA-Art50.4",
        "article": "Art. 50(4)",
        "requirement": "AI-generated content labeling",
        "description": (
            "Providers of AI systems that generate synthetic text, audio, "
            "image, or video content must ensure the outputs are marked in a "
            "machine-readable format and are detectable as artificially "
            "generated or manipulated.  AI agents producing text, code, "
            "images, or other content must embed appropriate metadata or "
            "watermarks to enable downstream identification of the content "
            "as AI-generated, supporting the broader ecosystem of content "
            "authenticity and provenance."
        ),
    },
    # Article 27 -- Fundamental Rights Impact Assessment
    {
        "id": "EUAIA-Art27",
        "article": "Art. 27",
        "requirement": "Fundamental Rights Impact Assessment (FRIA)",
        "description": (
            "Before deploying a high-risk AI system, deployers that are "
            "bodies governed by public law or private entities providing "
            "public services, as well as deployers of certain high-risk AI "
            "systems (such as those used for creditworthiness assessment or "
            "risk assessment and pricing in life and health insurance), must "
            "perform an assessment of the impact of the use of the AI system "
            "on fundamental rights.  AI agents classified as high-risk and "
            "deployed by public bodies or private entities affecting "
            "fundamental rights must be subject to a documented FRIA that "
            "evaluates impacts on equality, non-discrimination, privacy, "
            "freedom of expression, access to justice, and other "
            "fundamental rights enshrined in the EU Charter."
        ),
    },
    # Article 43 -- Conformity Assessment
    {
        "id": "EUAIA-Art43",
        "article": "Art. 43",
        "requirement": "Conformity assessment procedures",
        "description": (
            "High-risk AI systems must undergo a conformity assessment before "
            "being placed on the market or put into service, to demonstrate "
            "compliance with the requirements of the EU AI Act.  Depending "
            "on the classification, this may involve internal control "
            "procedures or assessment by a notified body.  AI agents "
            "classified as high-risk must complete the applicable conformity "
            "assessment procedure, maintain records of compliance, and affix "
            "the CE marking where required, ensuring that all technical, "
            "governance, and transparency requirements have been verified."
        ),
    },
    # Article 72 -- Post-Market Monitoring
    {
        "id": "EUAIA-Art72",
        "article": "Art. 72",
        "requirement": "Post-market monitoring system",
        "description": (
            "Providers of high-risk AI systems must establish and document a "
            "post-market monitoring system in a manner that is proportionate "
            "to the nature of the AI system and the risks involved.  This "
            "system must actively and systematically collect, document, and "
            "analyse relevant data provided by deployers or collected through "
            "other sources on the performance of the AI system throughout its "
            "lifetime.  AI agents must implement continuous monitoring "
            "capabilities that detect performance degradation, emerging "
            "risks, distribution drift, adversarial exploitation, and "
            "incidents, with defined procedures for corrective action and "
            "reporting to authorities when necessary."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to EU AI Act checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "EUAIA-Art6": [
        "risk classification", "risk level", "high-risk", "high risk",
        "prohibited ai", "risk category", "risk assessment",
        "risk-based approach",
    ],
    "EUAIA-Art5.1.a": [
        "social scoring", "social credit", "trustworthiness score",
        "behavioural scoring", "citizen score", "public authority scoring",
    ],
    "EUAIA-Art5.1.b": [
        "exploitation", "vulnerable", "vulnerability exploitation",
        "age exploitation", "disability", "manipulation of vulnerable",
        "children", "elderly", "cognitive impairment",
    ],
    "EUAIA-Art5.1.c": [
        "biometric categorization", "biometric classification",
        "racial classification", "political opinion", "race inference",
        "sensitive attribute inference", "protected characteristic",
    ],
    "EUAIA-Art5.1.d": [
        "biometric identification", "facial recognition",
        "real-time biometric", "remote identification",
        "surveillance", "public space monitoring",
    ],
    "EUAIA-Art9": [
        "risk management", "risk mitigation", "risk analysis",
        "risk treatment", "lifecycle risk", "residual risk",
        "foreseeable risk", "risk management system",
    ],
    "EUAIA-Art10": [
        "data governance", "training data", "data quality",
        "dataset bias", "data representativeness", "data preparation",
        "validation data", "testing data", "data suitability",
    ],
    "EUAIA-Art11": [
        "technical documentation", "system documentation",
        "design specification", "model documentation",
        "development methodology", "documentation requirements",
    ],
    "EUAIA-Art12": [
        "record-keeping", "logging", "audit trail", "event recording",
        "traceability", "audit log", "operational log",
        "activity recording",
    ],
    "EUAIA-Art13": [
        "transparency", "deployer information", "instructions for use",
        "system limitations", "intended purpose", "capability disclosure",
        "output interpretation",
    ],
    "EUAIA-Art14": [
        "human oversight", "human-in-the-loop", "human intervention",
        "human control", "override", "shutdown", "kill switch",
        "human supervision", "human review",
    ],
    "EUAIA-Art15": [
        "accuracy", "robustness", "cybersecurity", "adversarial",
        "data poisoning", "model manipulation", "prompt injection",
        "resilience", "adversarial attack", "model extraction",
    ],
    "EUAIA-Art53": [
        "gpai", "general-purpose ai", "general purpose ai",
        "foundation model", "training data summary", "copyright",
        "model documentation", "model card",
    ],
    "EUAIA-Art55": [
        "systemic risk", "systemic risk assessment", "adversarial testing",
        "red teaming", "model evaluation", "serious incident",
        "systemic risk gpai",
    ],
    "EUAIA-Art50.1": [
        "ai disclosure", "ai interaction", "interacting with ai",
        "chatbot disclosure", "bot disclosure", "ai system disclosure",
        "user notification of ai",
    ],
    "EUAIA-Art50.2": [
        "emotion recognition", "sentiment analysis", "biometric",
        "emotion detection", "affective computing",
        "facial expression analysis",
    ],
    "EUAIA-Art50.3": [
        "deep fake", "deepfake", "synthetic media", "manipulated content",
        "face swap", "video manipulation", "audio manipulation",
    ],
    "EUAIA-Art50.4": [
        "ai-generated content", "content labeling", "watermark",
        "content provenance", "synthetic content", "machine-readable label",
        "ai-generated text", "content authenticity",
    ],
    "EUAIA-Art27": [
        "fundamental rights", "impact assessment", "fria",
        "fundamental rights impact", "equality", "non-discrimination",
        "human rights impact", "rights assessment",
    ],
    "EUAIA-Art43": [
        "conformity assessment", "ce marking", "notified body",
        "compliance assessment", "conformity procedure",
        "internal control", "certification",
    ],
    "EUAIA-Art72": [
        "post-market monitoring", "post-market", "market surveillance",
        "performance monitoring", "continuous monitoring",
        "performance degradation", "distribution drift",
        "incident reporting",
    ],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of EU AI Act check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_eu_ai_act(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate EU AI Act compliance based on security findings and agent results.

    This function maps security findings to the relevant EU AI Act articles and
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
        A populated :class:`~aisec.core.models.ComplianceChecklist` for the
        EU AI Act.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in EU_AI_ACT_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in EU_AI_ACT_CHECKS:
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

    total = len(EU_AI_ACT_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="EU AI Act (Regulation (EU) 2024/1689)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
