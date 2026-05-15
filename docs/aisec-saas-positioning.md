# AiSec Product Positioning

> Strategic positioning updated for the OrchestAI integration path - May 2026

## Vision

AiSec is the risk and compliance evaluation layer for AI orchestration
platforms.

It helps products such as OrchestAI evaluate the models, providers, agents, RAG
pipelines, tools, memory, and workflows they orchestrate. AiSec can also run as
a standalone scanner for deeper security audits, but the primary product
direction is integration: make AI risk measurable inside the platforms where
models are selected, approved, routed, and monitored.

## Category

AiSec sits between three existing categories:

- Application security scanners.
- AI governance/compliance tools.
- AI observability/model operations platforms.

The differentiated category is:

```text
AI Risk Evaluation Engine for Model Orchestrators
```

Longer-term, this becomes part of:

```text
AI Security Posture Management
```

## Problem

AI orchestration platforms decide which model, provider, tool, RAG collection,
and workflow should handle a request. That decision is increasingly regulated
and security-sensitive.

The platform needs to know:

- What data classes does this model route process?
- Which provider receives the data?
- Is RAG enabled?
- Are retrieved documents filtered?
- Can the model call tools or MCP servers?
- Is memory enabled?
- Are PII redaction, retention, audit logging, rate limiting, and tenant
  isolation active?
- Which compliance frameworks are affected?
- Can the result be stored as evidence?

Traditional scanners do not answer those questions. Manual assessments do not
scale. A compliance module needs a machine-readable evaluator.

## Solution

AiSec accepts a descriptor of the AI target and returns normalized risk evidence.

```text
Orchestrator
  -> ModelRiskEvaluationRequest
  -> AiSec
  -> ModelRiskEvaluationResult
  -> Governance / approval / audit / CI policy
```

The same engine can optionally trigger deeper scans for Dockerized agents,
runtime behavior, RAG implementations, MCP servers, and infrastructure.

## First Integration Target

The first target integration is OrchestAI:

```text
git@gitlab.com:xcapit/orchestai.git
```

In OrchestAI, AiSec should appear as an optional evaluator in the compliance
module:

```text
Compliance Evaluators
  - Internal baseline evaluator
  - Privacy evaluator
  - Drift/quality evaluator
  - AiSec advanced AI security evaluator
```

## Product Surfaces

### 1. Embedded Evaluation

Command:

```bash
aisec evaluate model --input request.json --output result.json
```

Use cases:

- Model approval.
- Provider onboarding.
- RAG workflow review.
- Tool/MCP risk review.
- Tenant-specific compliance evidence.
- CI advisory or blocking gate.

### 2. Deep Scan

Command:

```bash
aisec scan run myagent:latest --format json,html,sarif
```

Use cases:

- Containerized agent audit.
- Runtime monitoring.
- Supply chain and infra checks.
- Advanced security assessment.

### 3. API/Dashboard

Command:

```bash
aisec serve
```

Use cases:

- Centralized evaluation service.
- Dashboard.
- Scheduled scans.
- Webhooks.
- Metrics and audit history.

## Differentiators

| Capability | AiSec | Generic SAST/SCA | AI observability | Manual compliance |
| --- | --- | --- | --- | --- |
| Model/provider risk descriptor | Yes | No | Partial | Manual |
| RAG security mapping | Yes | No | Partial | Manual |
| Tool/MCP/agentic risk | Yes | No | Partial | Manual |
| Privacy and PII safeguards | Yes | Partial | Partial | Manual |
| OWASP LLM/Agentic mapping | Yes | No | No | Manual |
| NIST AI RMF / ISO 42001 evidence | Yes | No | Partial | Manual |
| CLI/CI/CD gate | Yes | Yes | Rare | No |
| Deep Docker agent scan | Yes | Partial | No | Manual |
| Machine-readable evidence | Yes | Partial | Partial | Often no |

## Target Customers

### Primary: AI Platform Teams

Teams building internal or commercial AI orchestration products.

Need:

- Pluggable model-risk evaluator.
- Evidence for model/provider/workflow approval.
- CI and governance integration.
- Clear framework mappings.

### Secondary: DevSecOps for AI Products

Teams shipping RAG, agents, MCP servers, and LLM-powered workflows.

Need:

- CI gate.
- SARIF/JSON artifacts.
- Findings with remediation.
- Minimal adoption friction.

### Tertiary: Security and Compliance Teams

Teams that need evidence for AI governance programs.

Need:

- NIST AI RMF / ISO 42001 / GDPR / Habeas Data evidence.
- Historical evaluations.
- Risk trends.
- Exception and acceptance workflows.

## Packaging Direction

### Open Source Core

- CLI.
- Local evaluator.
- Deep scan engine.
- JSON outputs.
- Basic reports.
- GitLab/GitHub examples.

### Team / Platform

- Central API.
- Evaluation history.
- Project/workspace configuration.
- CI integration templates.
- Baseline comparison.

### Enterprise / Managed

- Multi-tenant service.
- SSO/RBAC.
- Approval workflows.
- Exception management.
- Evidence packs.
- Runtime integrations.
- On-prem/VPC deployment.

## 2026 Go-To-Market

### Phase 1: OrchestAI Integration

Goal: prove AiSec as an optional compliance evaluator inside a real model
orchestrator.

Deliverables:

- Stable protocol.
- OrchestAI adapter.
- Evaluation artifacts.
- Governance/evidence flow.

### Phase 2: Reusable Orchestrator Pattern

Goal: make the same pattern usable by other products.

Deliverables:

- Generic docs.
- JSON Schema.
- Reference adapters.
- Profiles for model, RAG, agent, workflow.

### Phase 3: CI/CD Adoption

Goal: make risk evaluation part of AI delivery pipelines.

Deliverables:

- GitLab CI template.
- GitHub Action template.
- Policy gates.
- MR/PR summary artifacts.

### Phase 4: Posture and Evidence Platform

Goal: aggregate evaluations into AI security posture.

Deliverables:

- Evaluation history.
- Baseline diff.
- Trends.
- Exception workflows.
- Framework evidence exports.

## Metrics

| Metric | Target |
| --- | --- |
| Time to integrate first evaluator | < 1 day |
| Time to run descriptor evaluation | < 10 seconds |
| Result schema stability | No breaking minor changes |
| Finding explainability | 100% with evidence + remediation |
| Framework mapping coverage | OWASP LLM, OWASP Agentic, NIST AI RMF, ISO 42001, GDPR, Habeas Data |

## Positioning Statement

AiSec is an optional AI risk and compliance evaluator for platforms that
orchestrate models, agents, RAG, tools, and workflows. It turns configuration
and runtime context into machine-readable findings, framework mappings, policy
verdicts, and audit evidence.
