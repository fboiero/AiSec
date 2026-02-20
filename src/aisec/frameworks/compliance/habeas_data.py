"""Argentina Ley 25.326 (Habeas Data) compliance checks for AI agents.

This module defines the key articles of Argentina's Personal Data Protection
Law (Ley 25.326 de Proteccion de los Datos Personales) relevant to AI agent
systems and provides an evaluation function that maps security findings and
agent results to a :class:`~aisec.core.models.ComplianceChecklist`.

Reference: http://servicios.infoleg.gob.ar/infolegInternet/anexos/60000-64999/64790/norma.htm
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
# Habeas Data (Ley 25.326) Compliance Checks
# ---------------------------------------------------------------------------

HABEAS_DATA_CHECKS: list[dict[str, str]] = [
    # Art. 2 -- Definiciones
    {
        "id": "HD-Art2",
        "article": "Art. 2 - Definiciones",
        "requirement": "Definitions of personal data and sensitive data",
        "description": (
            "The law defines 'datos personales' (personal data) as information "
            "of any kind referring to specific or determinable natural or legal "
            "persons, and 'datos sensibles' (sensitive data) as data revealing "
            "racial or ethnic origin, political opinions, religious or "
            "philosophical beliefs, trade union membership, health, or sexual "
            "orientation.  AI agents must correctly classify data categories "
            "to apply appropriate protections."
        ),
    },
    # Art. 3 -- Archivos de datos - Licitud
    {
        "id": "HD-Art3",
        "article": "Art. 3 - Archivos de datos - Licitud",
        "requirement": "Lawful formation of data files",
        "description": (
            "Data files, registers, or databases that handle personal data "
            "must be lawfully registered.  AI agent systems that create or "
            "maintain repositories of personal data must ensure their data "
            "stores are registered with the appropriate authority (AAIP) and "
            "comply with lawful formation requirements."
        ),
    },
    # Art. 4 -- Calidad de los datos
    {
        "id": "HD-Art4.1",
        "article": "Art. 4(1) - Calidad de los datos",
        "requirement": "Data quality: accurate, complete, and up to date",
        "description": (
            "Personal data collected must be accurate, adequate, relevant, and "
            "not excessive in relation to the scope and purpose for which it "
            "was obtained.  AI agents must ensure the personal data they "
            "process is current, complete, and not used beyond the original "
            "purpose of collection."
        ),
    },
    {
        "id": "HD-Art4.3",
        "article": "Art. 4(3) - Calidad de los datos",
        "requirement": "Data must not be used for purposes incompatible with collection",
        "description": (
            "Data collected for one purpose must not be used for purposes "
            "incompatible with the original intent without fresh consent.  "
            "AI agents must not repurpose personal data beyond the scope "
            "communicated at the time of collection."
        ),
    },
    # Art. 5 -- Consentimiento
    {
        "id": "HD-Art5",
        "article": "Art. 5 - Consentimiento",
        "requirement": "Consent requirement for data processing",
        "description": (
            "The processing of personal data is unlawful without the free, "
            "express, and informed consent of the data subject.  Consent must "
            "be given in writing or by an equivalent means, depending on the "
            "circumstances.  AI agents must not process personal data without "
            "verified consent, unless a legal exception applies."
        ),
    },
    # Art. 6 -- Informacion
    {
        "id": "HD-Art6",
        "article": "Art. 6 - Informacion",
        "requirement": "Information to the data subject",
        "description": (
            "When personal data is collected, the data subject must be "
            "informed of the purpose of processing, the recipients of the "
            "data, the identity of the data controller, and the rights of "
            "access, rectification, and deletion.  AI agent interactions "
            "that collect personal data must provide this information clearly."
        ),
    },
    # Art. 7 -- Categorias de datos
    {
        "id": "HD-Art7.1",
        "article": "Art. 7(1) - Categorias de datos",
        "requirement": "Prohibition of collecting sensitive data without justification",
        "description": (
            "No person may be compelled to provide sensitive data.  Sensitive "
            "data may only be collected and processed when there are reasons "
            "of general interest authorised by law, for statistical or "
            "scientific purposes when the data subject cannot be identified.  "
            "AI agents must not collect sensitive data without explicit legal "
            "justification."
        ),
    },
    {
        "id": "HD-Art7.3",
        "article": "Art. 7(3) - Categorias de datos",
        "requirement": "Prohibition of databases exclusively storing sensitive data",
        "description": (
            "The formation of data files, banks, or registers that store "
            "information exclusively revealing sensitive data is prohibited.  "
            "AI agent data stores must not be designed to exclusively "
            "catalogue sensitive personal attributes."
        ),
    },
    # Art. 8 -- Datos relativos a la salud
    {
        "id": "HD-Art8",
        "article": "Art. 8 - Datos relativos a la salud",
        "requirement": "Health data protections",
        "description": (
            "Health-related data may only be processed by health "
            "establishments or professionals subject to professional secrecy "
            "obligations.  AI agents that process health data must operate "
            "under the supervision of qualified health professionals and "
            "enforce strict access controls."
        ),
    },
    # Art. 11 -- Seguridad de los datos
    {
        "id": "HD-Art11",
        "article": "Art. 11 - Seguridad de los datos",
        "requirement": "Data security obligations",
        "description": (
            "The data controller must adopt technical and organisational "
            "measures necessary to guarantee the security and "
            "confidentiality of personal data, in order to prevent their "
            "adulteration, loss, unauthorised consultation, or processing.  "
            "AI agent systems must implement appropriate security controls "
            "including encryption, access control, and audit logging."
        ),
    },
    # Art. 12 -- Cesion (Transferencia internacional)
    {
        "id": "HD-Art12",
        "article": "Art. 12 - Cesion",
        "requirement": "International data transfers",
        "description": (
            "The transfer of personal data to countries or international "
            "organisations that do not provide adequate levels of protection "
            "is prohibited, with limited exceptions.  AI agent architectures "
            "that transmit data to cloud services or third-party APIs in "
            "other jurisdictions must verify adequacy or apply appropriate "
            "safeguards."
        ),
    },
    # Art. 14 -- Derecho de acceso
    {
        "id": "HD-Art14",
        "article": "Art. 14 - Derecho de acceso",
        "requirement": "Right of access to personal data",
        "description": (
            "The data subject has the right to request and obtain information "
            "about their personal data held in public or private data files.  "
            "This right may be exercised free of charge at intervals of no "
            "less than six months, unless a legitimate interest is proven.  "
            "AI agent systems must support data subject access requests."
        ),
    },
    # Art. 16 -- Derecho de rectificacion, actualizacion o supresion
    {
        "id": "HD-Art16",
        "article": "Art. 16 - Derecho de rectificacion, actualizacion o supresion",
        "requirement": "Right of rectification and deletion",
        "description": (
            "Every person has the right to have their personal data rectified, "
            "updated, and, where appropriate, deleted or subjected to "
            "confidentiality.  The data controller must process rectification "
            "or deletion within five business days.  AI agent memory stores "
            "and databases must support timely rectification and deletion."
        ),
    },
    # Art. 26 -- Prestacion de servicios de seguridad del Estado
    {
        "id": "HD-Art26",
        "article": "Art. 26 - Prestacion de servicios informatizados",
        "requirement": "Data files for state security purposes",
        "description": (
            "Data files maintained for state security, defence, or the "
            "prevention, investigation, and prosecution of crimes are subject "
            "to specific provisions.  AI agents operating in public security "
            "contexts must comply with the enhanced protections and "
            "restrictions applicable to these categories of data files."
        ),
    },
    # Art. 27 -- Archivos con fines de publicidad
    {
        "id": "HD-Art27",
        "article": "Art. 27 - Archivos, registros o bancos de datos con fines de publicidad",
        "requirement": "Marketing data files and the right to object",
        "description": (
            "When personal data is used for advertising or marketing purposes, "
            "the data subject has the right to be informed and to object.  "
            "AI agents involved in personalised marketing or recommendation "
            "systems must provide opt-out mechanisms and honour objections."
        ),
    },
    # Art. 31 -- Sanciones
    {
        "id": "HD-Art31",
        "article": "Art. 31 - Sanciones",
        "requirement": "Sanctions for non-compliance",
        "description": (
            "The supervisory authority (AAIP) may impose sanctions including "
            "warnings, suspension of database operations, fines, and closure "
            "of data files for violations of the law.  Organisations deploying "
            "AI agents must understand the sanction regime and implement "
            "controls to avoid violations."
        ),
    },
]


# ---------------------------------------------------------------------------
# Keywords used to match findings to Habeas Data checks
# ---------------------------------------------------------------------------

_CHECK_KEYWORDS: dict[str, list[str]] = {
    "HD-Art2": [
        "personal data", "sensitive data", "datos personales",
        "datos sensibles", "data classification",
    ],
    "HD-Art3": [
        "data file registration", "database registration", "lawful formation",
        "data registry",
    ],
    "HD-Art4.1": [
        "data quality", "accuracy", "data accuracy", "outdated data",
        "incomplete data",
    ],
    "HD-Art4.3": [
        "purpose limitation", "repurpose", "secondary use",
        "incompatible purpose",
    ],
    "HD-Art5": [
        "consent", "consentimiento", "informed consent", "consent mechanism",
    ],
    "HD-Art6": [
        "information provision", "notice", "data subject information",
        "transparency",
    ],
    "HD-Art7.1": [
        "sensitive data collection", "datos sensibles",
        "special categories", "health data", "political opinion",
        "religious belief",
    ],
    "HD-Art7.3": [
        "sensitive data store", "sensitive data database",
        "exclusive sensitive data",
    ],
    "HD-Art8": [
        "health data", "medical data", "datos de salud",
        "health information",
    ],
    "HD-Art11": [
        "data security", "security measures", "encryption",
        "access control", "audit log", "confidentiality",
        "unauthorised access", "data breach",
    ],
    "HD-Art12": [
        "international transfer", "cross-border", "data transfer",
        "cloud service", "third-party jurisdiction", "data export",
    ],
    "HD-Art14": [
        "right of access", "access request", "data access",
        "derecho de acceso",
    ],
    "HD-Art16": [
        "rectification", "deletion", "erasure", "data removal",
        "right to delete", "update personal data", "supresion",
    ],
    "HD-Art26": [
        "state security", "law enforcement", "public security",
        "defence data", "crime prevention",
    ],
    "HD-Art27": [
        "marketing", "advertising", "publicidad", "opt-out",
        "direct marketing", "recommendation",
    ],
    "HD-Art31": [
        "sanctions", "penalty", "fine", "non-compliance",
        "violation", "enforcement",
    ],
}


def _match_finding_to_checks(finding: Finding) -> list[str]:
    """Return the list of Habeas Data check IDs relevant to a finding."""
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    matched: list[str] = []
    for check_id, keywords in _CHECK_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            matched.append(check_id)
    return matched


def evaluate_habeas_data(
    findings: list[Finding],
    agent_results: list[AgentResult],
) -> ComplianceChecklist:
    """Evaluate Habeas Data (Ley 25.326) compliance based on findings.

    This function maps security findings to the relevant articles of
    Argentina's Ley 25.326 and produces a
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
        Ley 25.326.
    """
    # Collect all findings from agent results as well.
    all_findings: list[Finding] = list(findings)
    for result in agent_results:
        all_findings.extend(result.findings)

    # Build a mapping: check_id -> list of matched findings.
    check_findings: dict[str, list[Finding]] = {
        check["id"]: [] for check in HABEAS_DATA_CHECKS
    }
    for finding in all_findings:
        for check_id in _match_finding_to_checks(finding):
            if check_id in check_findings:
                check_findings[check_id].append(finding)

    items: list[ComplianceCheckItem] = []
    passed = 0
    failed = 0
    not_applicable = 0

    for check in HABEAS_DATA_CHECKS:
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

    total = len(HABEAS_DATA_CHECKS)
    partial = total - passed - failed - not_applicable

    return ComplianceChecklist(
        framework_name="Ley 25.326 - Proteccion de los Datos Personales (Habeas Data)",
        total_checks=total,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        items=items,
    )
