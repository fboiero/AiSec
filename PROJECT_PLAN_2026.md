# AiSec 2026 Project Plan

## Mission

Make AI model, agent, RAG, and workflow risk measurable for platforms that
orchestrate AI systems.

AiSec must serve two surfaces:

1. **Integrated evaluator**: a stable optional engine that products such as
   OrchestAI can call from their compliance module.
2. **Deep scanner**: a standalone CLI/API scanner for Dockerized AI agents and
   agentic applications.

## Product Thesis

AI orchestration platforms need a compliance/risk layer that understands models,
providers, tools, RAG, memory, MCP, data classes, safeguards, and jurisdiction.
AiSec should be that layer: small enough to run in CI, structured enough to feed
governance workflows, and deep enough to run specialized scans when needed.

## Current Baseline

As of May 2026:

- Version: `1.10.0` local.
- 36 security agents.
- CLI, API, dashboard, report renderers, audit trail, OpenAPI, metrics,
  scheduler, scan history, Kubernetes/Helm/Docker Compose assets.
- Model-risk protocol: `aisec.model_risk.v1`.
- Command: `aisec evaluate model`.
- First integration target: OrchestAI.
- Tests: 1,479 passing and 9 skipped in local `.venv` with `.[api,dev]`.
- Correlation rules: 40 total, including 9 centered on `agentic_review`.

## 2026 Outcomes

| Outcome | Definition |
| --- | --- |
| Orchestrator-ready protocol | OrchestAI and similar systems can call AiSec without importing internal code. |
| Compliance evidence engine | Results can be stored as immutable evidence for model/provider/workflow approval. |
| CI/CD gate | Teams can run AiSec in GitLab/GitHub and block high-risk AI changes. |
| Deep scan path | Existing Docker/agent scan remains available for advanced audits. |
| Enterprise posture foundation | AiSec can evolve into AI Security Posture Management without changing the integration contract. |

## Current Implementation Snapshot

Implemented in the local v1.10.0 workspace:

- Descriptor-based model-risk evaluator with `aisec.model_risk.v1`.
- Deterministic `ModelRiskEvaluationResult` JSON for the same request payload.
- CLI schema export for request/result contracts.
- API endpoint for service-to-service model-risk evaluation:
  `POST /api/evaluate/model/`.
- API-mode evaluation history for persisted model-risk evidence:
  `GET /api/evaluations/` and `GET /api/evaluations/{evaluation_id}/`.
- API-mode posture rollup:
  `GET /api/evaluations/rollup/`.
- Approved model-risk baseline library for API mode:
  `GET/POST /api/evaluation-baselines/`.
- Accepted model-risk exceptions for API mode:
  `GET/POST /api/evaluation-exceptions/`.
- Example OrchestAI request/result artifacts and two validated OrchestAI
  use-case fixtures.
- Python subprocess adapter handling missing binary, timeout, policy failure,
  and invalid output as distinct outcomes.
- Python HTTP adapter for `aisec serve` handling endpoint errors, timeouts,
  invalid output, and valid policy failures as distinct outcomes.
- Reusable orchestrator adapter guide for integrating platforms beyond
  OrchestAI.
- Managed deployment path for shared service-mode AiSec using Docker Compose,
  Kubernetes, or Helm.
- GitHub Actions and GitLab CI examples for advisory/blocking model-risk gates.
- CI artifact parser and Markdown/JSON summary command for model-risk results.
- Framework evidence export command for model-risk compliance records.
- Baseline comparison command for current versus approved model-risk evidence.
- Baseline comparison separates accepted and unaccepted new findings so
  governance gates can tolerate explicitly approved exceptions.
- `agentic_review` meta-agent for agent-on-agent review, delegation, handoff,
  identity, memory, dissent, and human-escalation analysis.
- 40 correlation rules, 9 centered on `agentic_review`.
- Canonical external-agent handoff: `docs/AGENT_HANDOFF.md`.

## Q2 2026: Integration Foundation

### Objective

Turn AiSec from a scanner into an optional risk evaluator that can be embedded
into OrchestAI-style compliance flows.

### Deliverables

- `ModelRiskEvaluationRequest` and `ModelRiskEvaluationResult` contracts.
- `aisec evaluate model --input request.json --output result.json`.
- OrchestAI integration protocol documentation.
- Example request/result for RAG + PII + tools.
- Policy verdict support: `pass`, `warn`, `fail`.
- Adapter guidance for CLI, container, and future API modes.
- Tests for schema validation, findings, policy verdicts, and CLI output.

### Acceptance Criteria

- OrchestAI can invoke AiSec as an external process.
- AiSec returns deterministic JSON that OrchestAI can store.
- Missing AiSec binary or timeout can be handled by OrchestAI as optional
  evaluator failure, not platform failure.
- All findings include severity, framework mapping, evidence, and remediation.

## Q3 2026: Orchestrator Adapter Maturity

### Objective

Make AiSec useful across multiple AI orchestration products, not only OrchestAI.

### Deliverables

- Stable schema documentation with versioning rules.
- JSON Schema export for request/result.
- Container image optimized for `aisec evaluate model`.
- GitLab CI and GitHub Actions examples for orchestrator repos.
- Reference adapters:
  - Python subprocess adapter.
  - HTTP client adapter for `aisec serve`.
  - CI artifact summary adapter.
- Profiles for common orchestrator targets:
  - LLM provider route.
  - RAG pipeline.
  - Agent with tools.
  - MCP-enabled workflow.
  - Multi-tenant support assistant.

### Acceptance Criteria

- A consuming platform can add AiSec in less than one day.
- Results remain compatible across minor versions.
- Advisory mode and blocking mode are both documented.
- Framework mappings are clear enough for governance teams.

## Q4 2026: Evidence, Governance, and Posture

### Objective

Move from one-off evaluations to continuous model-risk evidence and posture.

### Deliverables

- Baseline promotion workflow in consuming governance UIs.
- Risk trend rollups by target, provider, workflow, framework, and tenant.
- Exception/acceptance metadata for policy gates.
- Export packs for:
  - ISO/IEC 42001 evidence.
  - NIST AI RMF evidence.
  - GDPR/Habeas Data privacy evidence.
  - OWASP LLM and Agentic technical findings.
- Runtime extension path combining descriptor evaluation with deep scans and
  Falco/runtime events.

### Acceptance Criteria

- AiSec can support a governance screen in OrchestAI.
- Compliance teams can retrieve historical evidence for a model approval.
- Engineering teams can compare current risk against the previous approved
  baseline.

## 2027 Direction

### AI Security Posture Management

AiSec should evolve into a posture engine that can inventory and score AI
systems across an organization:

- Models and providers.
- RAG stores and data classes.
- Agents and tools.
- MCP servers.
- Workflows.
- Runtime signals.
- Compliance controls.
- Exceptions and approvals.

The open-source core should remain usable locally, while commercial or internal
platform deployments can add multi-tenancy, workflow approvals, and dashboards.

## Non-Goals

- AiSec does not replace an orchestrator such as OrchestAI.
- AiSec does not certify ISO 42001, SOC 2, GDPR, or other frameworks by itself.
- AiSec does not require consuming products to import AiSec internals.
- AiSec should not become tightly coupled to one product's database or domain
  models.

## Engineering Principles

- JSON contract first.
- Optional integration first.
- Evidence is immutable.
- Every finding must be explainable.
- Framework mappings must be explicit.
- Deep scans are additive, not mandatory.
- Backward compatibility matters more than feature churn.
