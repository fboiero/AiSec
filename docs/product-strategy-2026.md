# AiSec Product Strategy 2026

## Strategic Shift

AiSec started as a deep security scanner for autonomous AI agents. That remains
valuable, but the stronger product direction is broader:

```text
AiSec is an optional AI risk and compliance evaluator for model orchestrators.
```

OrchestAI is the first concrete target. The same pattern should work for other
platforms that route prompts across models, providers, tools, RAG, memory, MCP,
and workflows.

## Product Architecture

```text
AI platform / model orchestrator
  -> evaluator adapter
  -> AiSec JSON contract
  -> risk result
  -> governance, approval, audit, CI/CD
```

AiSec must not require direct imports into the consuming platform. The boundary
is JSON.

## Ideal Customer Profile

### Primary

AI platform teams building products similar to OrchestAI.

They need:

- Pluggable compliance evaluators.
- Model/provider approval.
- RAG and agent risk checks.
- Framework evidence.
- Optional CI gates.

### Secondary

Security teams reviewing internal AI systems.

They need:

- Evidence.
- Findings.
- Risk scoring.
- Historical comparison.

### Tertiary

DevSecOps teams shipping agentic applications.

They need:

- CLI.
- CI integration.
- SARIF/JSON reports.
- Container scans.

## Wedge

The wedge is not "another scanner". The wedge is:

```text
Add AiSec as the advanced AI-security evaluator inside your orchestration
platform's compliance module.
```

This is lower friction than selling a complete governance platform immediately.

## Product Layers

### Layer 1: Local Evaluator

- `aisec evaluate model`.
- JSON request/result.
- Fast, deterministic descriptor evaluation.
- No Docker required.

### Layer 2: Deep Scan

- `aisec scan run`.
- Docker sandbox.
- Specialized agents.
- Runtime and infrastructure checks.

### Layer 3: Service Mode

- `aisec serve`.
- API.
- Dashboard.
- History.
- Metrics.
- Webhooks.

### Layer 4: Governance/Posture

- Evaluation history.
- Baselines.
- Exceptions.
- Approval workflows.
- Evidence exports.

## 90-Day Plan

### Days 0-30

- Stabilize `aisec.model_risk.v1`.
- Implement OrchestAI adapter.
- Add JSON Schema for request/result.
- Improve examples for:
  - model route,
  - RAG pipeline,
  - tool-enabled agent,
  - MCP workflow.
- Update docs and CI examples.

### Days 31-60

- Completed: API endpoint for model-risk evaluation.
- Completed: baseline comparison for evaluation results.
- Completed: Markdown/JSON summary renderer for model-risk results.
- Completed: GitHub Actions and GitLab CI artifact examples.
- Completed: API-mode evaluation history, posture rollup, and approved
  baseline library.
- Completed: API-mode exception/acceptance metadata for finding fingerprints.
- Completed: framework evidence exports for model-risk artifacts.
- Completed: validation against two OrchestAI use cases.
- Completed: reusable adapter guide for other orchestrators.
- Completed: managed deployment path for service-mode AiSec.

### Days 61-90

- Harden managed deployment path for external pilots.

## Success Metrics

| Metric | Target |
| --- | --- |
| OrchestAI adapter integration | Working optional evaluator |
| Descriptor evaluation runtime | < 10 seconds |
| Schema stability | No breaking changes in v1 |
| False-positive calibration | Findings are explainable and suppressible |
| Evidence utility | Results can be stored directly in governance |

## Positioning

Short:

```text
AiSec evaluates AI model, RAG, agent, and workflow risk for orchestrators.
```

Long:

```text
AiSec is an open-source AI risk and compliance engine that model orchestrators
can call to evaluate models, providers, RAG pipelines, tools, MCP, memory, and
agentic workflows. It returns normalized findings, framework mappings, policy
verdicts, and audit-ready evidence.
```
