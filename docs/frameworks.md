# Security Frameworks

AiSec maps findings to 8 compliance frameworks across AI security, privacy, and governance standards.

## OWASP LLM Top 10 (2025)

| ID | Name | Description |
|----|------|-------------|
| LLM01 | Prompt Injection | Manipulating LLM behavior through crafted inputs |
| LLM02 | Sensitive Information Disclosure | Unauthorized exposure of private data |
| LLM03 | Supply Chain | Compromised components in the LLM supply chain |
| LLM04 | Data and Model Poisoning | Manipulation of training data or models |
| LLM05 | Improper Output Handling | Inadequate validation of LLM outputs |
| LLM06 | Excessive Agency | Granting LLMs too much autonomy or access |
| LLM07 | System Prompt Leakage | Unauthorized extraction of system prompts |
| LLM08 | Vector and Embedding Weaknesses | Vulnerabilities in RAG pipelines |
| LLM09 | Misinformation | Generation of false or misleading content |
| LLM10 | Unbounded Consumption | Uncontrolled resource usage by LLMs |

## OWASP Top 10 for Agentic Applications (2026)

| ID | Name | Description |
|----|------|-------------|
| ASI01 | Agent Goal Hijacking | Manipulating agent objectives through adversarial inputs |
| ASI02 | Tool Misuse | Exploiting agent tool access for unauthorized actions |
| ASI03 | Identity and Privilege Abuse | Leveraging agent credentials beyond intended scope |
| ASI04 | Supply Chain Vulnerabilities | Compromised agent dependencies and integrations |
| ASI05 | Unexpected Code Execution | Agent executing unintended or malicious code |
| ASI06 | Memory and Context Poisoning | Corrupting agent memory or conversation context |
| ASI07 | Insecure Inter-Agent Communication | Exploiting communication between agents |
| ASI08 | Cascading Failures | Single agent failure propagating to dependent systems |
| ASI09 | Human-Agent Trust Exploitation | Abusing user trust in agent-generated content |
| ASI10 | Rogue Agents | Agents operating outside their designed boundaries |

## NIST AI Risk Management Framework

### Core Functions
- **GOVERN** - Policies, accountability, and risk culture
- **MAP** - Context, risk identification, and stakeholder analysis
- **MEASURE** - Assessment metrics, testing, and monitoring
- **MANAGE** - Risk response, incident management, continuous improvement

## NIST AI 600-1 (Generative AI Profile)

200+ action items across 12 GenAI-specific risk categories:

| Category | Risk Area | RMF Functions |
|----------|-----------|---------------|
| CBRN Information | Chemical, biological, radiological, nuclear info access | GOVERN, MAP, MEASURE, MANAGE |
| Confabulation | False information presented as fact | MAP, MEASURE, MANAGE |
| Data Privacy | Unauthorized personal data processing | GOVERN, MAP, MANAGE |
| Environmental | Energy and resource consumption | GOVERN, MAP, MANAGE |
| Human-AI Config | Inappropriate trust, over-reliance | GOVERN, MAP, MEASURE |
| Information Integrity | Misinformation, manipulation | GOVERN, MAP, MEASURE, MANAGE |
| Information Security | Cybersecurity vulnerabilities | GOVERN, MAP, MEASURE, MANAGE |
| Intellectual Property | Copyright, trademark violations | GOVERN, MAP |
| Obscene Content | Harmful, offensive material | GOVERN, MAP, MEASURE |
| Toxicity/Bias | Discriminatory or toxic outputs | GOVERN, MAP, MEASURE, MANAGE |
| Value Chain | Third-party component risks | GOVERN, MAP, MANAGE |
| Homogenization | Reduced diversity in outputs | MAP, MEASURE |

## EU AI Act (Regulation 2024/1689)

22 compliance checks covering:

| Article | Requirement |
|---------|------------|
| Art. 5 | Prohibited AI practices (social scoring, exploitation, biometric categorization, real-time remote biometric ID) |
| Art. 6 | Risk classification (prohibited / high-risk / limited / minimal) |
| Art. 9 | Risk management system |
| Art. 10 | Data and data governance |
| Art. 11 | Technical documentation |
| Art. 12 | Record-keeping and logging |
| Art. 13 | Transparency and information to deployers |
| Art. 14 | Human oversight measures |
| Art. 15 | Accuracy, robustness, and cybersecurity |
| Art. 27 | Fundamental Rights Impact Assessment (FRIA) |
| Art. 43 | Conformity assessment procedures |
| Art. 50 | Transparency obligations (AI disclosure, emotion recognition, deepfakes, content labeling) |
| Art. 53 | GPAI model provider obligations |
| Art. 55 | Systemic risk assessment for GPAI |
| Art. 72 | Post-market monitoring system |

## ISO/IEC 42001:2023 (AI Management System)

28 checks against the AIMS standard:

- **Clause 4**: Context of the organization (4.1-4.4)
- **Clause 5**: Leadership and commitment, AI policy, roles (5.1-5.3)
- **Clause 6**: Risk planning, AI objectives, change management (6.1-6.3)
- **Clause 7**: Resources, competence, awareness, communication, documentation (7.1-7.5)
- **Clause 8**: Operational planning, AI impact assessment, lifecycle, data management (8.1-8.4)
- **Clause 9**: Monitoring, internal audit, management review (9.1-9.3)
- **Clause 10**: Nonconformity, continual improvement (10.1-10.2)
- **Annex A**: AI controls (A.2-A.4, A.10)

## Argentina AI Governance

15 checks covering the Argentine AI regulatory landscape:

### Ley 25.326 (Habeas Data - AI Extension)
- Automated decision-making transparency
- Right to explanation for AI-processed personal data
- AI profiling restrictions with human intervention

### Bill 3003-D-2024 (AI Regulation Bill)
- High-risk AI system identification (Art. 4)
- Mandatory impact assessment (Art. 5)
- Traceability and auditability (Art. 6)
- Human oversight for public services (Art. 7)
- Transparency and explainability (Art. 8)
- Non-discrimination and fairness (Art. 9)
- Data protection alignment (Art. 10)

### AAIP (Agencia de Acceso a la Informacion Publica) Guidance
- AI system registration
- Privacy impact assessment for AI
- Cross-border data transfer for AI processing

### Provincial Protocols
- Facial recognition restrictions (Buenos Aires, Santa Fe)
- Public sector AI usage transparency

## Privacy Regulations

### GDPR (EU)
Key articles assessed: 5 (principles), 6 (lawful basis), 7 (consent), 13-14 (transparency), 15 (access), 17 (erasure), 25 (data protection by design), 32 (security), 35 (DPIA).

### CCPA (California)
Rights assessed: right to know, right to delete, right to opt-out, right to non-discrimination, notice at collection, data security.

### Habeas Data (Argentina, Ley 25.326)
Key articles: 2 (definitions), 4 (data quality), 5 (consent), 6 (information), 7 (sensitive data), 11 (data security), 12 (international transfers), 14 (right of access), 16 (rectification/deletion).
