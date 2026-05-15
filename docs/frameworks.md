# Frameworks And Evidence Mapping

AiSec maps model, agent, RAG, workflow, and scan findings to AI security,
privacy, and governance frameworks. The goal is not to replace legal or audit
judgment. The goal is to produce structured technical evidence that a platform
such as OrchestAI can store and review.

## Frameworks

| Framework | Purpose |
| --- | --- |
| OWASP LLM Top 10 | Technical risks in LLM applications. |
| OWASP Agentic Top 10 | Risks in agentic systems, tools, identity, memory, and inter-agent flows. |
| NIST AI RMF | Governance, mapping, measurement, and management of AI risk. |
| NIST AI 600-1 | Generative AI profile evidence and risk categories. |
| ISO/IEC 42001 | AI management system controls and lifecycle governance. |
| EU AI Act | AI risk classification, transparency, logging, oversight, and GPAI obligations. |
| GDPR | Personal data processing, transparency, minimization, security, DPIA. |
| CCPA | Privacy rights and data security for California consumers. |
| Habeas Data | Argentina Ley 25.326 obligations and personal data controls. |
| Argentina AI Governance | Emerging AI governance and public-sector controls. |

## Orchestrator-Relevant Controls

For OrchestAI-style platforms, the most important control groups are:

| Area | Example Checks |
| --- | --- |
| Model/provider routing | Provider, model ID, jurisdiction, data classes, retention expectations. |
| RAG | Retrieval filtering, document trust, tenant isolation, embedding PII risk. |
| Tools/MCP | Tool approval, least privilege, audit logging, output sanitization. |
| Memory | Retention policy, PII minimization, erasure workflows, poisoning controls. |
| Privacy | PII redaction, lawful basis/consent, prompt logging, cross-border transfer. |
| Governance | Human-in-the-loop, risk acceptance, audit trail, baseline comparison. |
| Abuse/cost | Rate limiting, extraction risk, unbounded consumption. |

## OWASP LLM Top 10

| ID | Name | OrchestAI/AiSec relevance |
| --- | --- | --- |
| LLM01 | Prompt Injection | User input and retrieved documents can override model or workflow intent. |
| LLM02 | Sensitive Information Disclosure | PII can leak to prompts, logs, providers, outputs, or embeddings. |
| LLM03 | Supply Chain | Models, dependencies, images, and providers can introduce risk. |
| LLM04 | Data and Model Poisoning | Training, fine-tuning, or retrieval data can be manipulated. |
| LLM05 | Improper Output Handling | Outputs can trigger unsafe downstream behavior. |
| LLM06 | Excessive Agency | Models can call tools or execute actions beyond intended scope. |
| LLM07 | System Prompt Leakage | Internal instructions can leak through responses or errors. |
| LLM08 | Vector and Embedding Weaknesses | RAG collections can leak, mix tenants, or retrieve poisoned content. |
| LLM09 | Misinformation | Unsupported outputs can create user or operational harm. |
| LLM10 | Unbounded Consumption | Abuse can create cost spikes, availability issues, or extraction risk. |

## OWASP Agentic Top 10

| ID | Name | OrchestAI/AiSec relevance |
| --- | --- | --- |
| ASI01 | Agent Goal Hijacking | Attackers redirect agent goals. |
| ASI02 | Tool Misuse | Tools are invoked outside intended policy. |
| ASI03 | Identity and Privilege Abuse | Agent credentials exceed least privilege. |
| ASI04 | Supply Chain Vulnerabilities | Skills, tools, models, or connectors are compromised. |
| ASI05 | Unexpected Code Execution | Model-driven execution escapes expected boundaries. |
| ASI06 | Memory and Context Poisoning | Persistent state is corrupted or leaks data. |
| ASI07 | Insecure Inter-Agent Communication | Messages between agents lack auth, integrity, or boundaries. |
| ASI08 | Cascading Failures | One model/agent failure propagates through workflows. |
| ASI09 | Human-Agent Trust Exploitation | Users over-trust agent output. |
| ASI10 | Rogue Agents | Agents operate outside defined ownership or control. |

## NIST AI RMF

AiSec maps findings to:

- `GOVERN`: policy, accountability, oversight, documentation.
- `MAP`: context, data classes, use case, stakeholders, jurisdiction.
- `MEASURE`: testing, monitoring, metrics, evidence.
- `MANAGE`: mitigations, decisions, incidents, continuous improvement.

## NIST AI 600-1

AiSec uses this as a GenAI evidence profile for:

- Data privacy.
- Information integrity.
- Information security.
- Human-AI interaction.
- Confabulation.
- Toxicity/bias.
- Value chain risk.
- Abuse and misuse.

## ISO/IEC 42001

AiSec findings can support evidence for:

- AI policy.
- Roles and responsibilities.
- Risk planning.
- AI impact assessment.
- Data management.
- Lifecycle controls.
- Monitoring and internal audit.
- Continual improvement.

## Privacy Frameworks

### GDPR

Common mappings:

- Article 5: principles, minimization, storage limitation.
- Article 6: lawful basis.
- Article 7: consent.
- Articles 13-15: transparency and access.
- Article 17: erasure.
- Article 25: data protection by design.
- Article 32: security of processing.
- Article 35: DPIA.

### Habeas Data Argentina

Common mappings:

- Data quality.
- Consent and information duties.
- Sensitive data.
- Data security.
- International transfer.
- Access, rectification, and deletion.

## Result Interpretation

AiSec returns framework-level rollups as advisory evidence:

- `pass`: no findings mapped to that framework in the evaluation.
- `warn`: findings exist below the configured failure threshold.
- `fail`: high or critical findings, or findings above the configured policy.

These statuses support governance workflows, but they are not legal
certifications.
