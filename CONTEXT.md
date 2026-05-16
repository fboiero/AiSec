# AiSec Session Context

## Current State

- **Version**: `1.10.0` local.
- **Branch**: `main`.
- **Release target**: `v1.10.0`.
- **Unit tests**: `1484 passed, 9 skipped` in local `.venv` with `.[api,dev]`.
- **Security agents**: `36`.
- **Correlation rules**: `40`.
- **Agent-on-agent correlation rules**: `9`.
- **Model-risk protocol**: `aisec.model_risk.v1`.
- **Primary evaluator command**: `aisec evaluate model`.
- **Primary evaluator API**: `POST /api/evaluate/model/`.
- **Evaluator history API**: `GET /api/evaluations/`.
- **Evaluator rollup API**: `GET /api/evaluations/rollup/`.
- **Evaluator baseline API**: `GET/POST /api/evaluation-baselines/`.
- **Evaluator exception API**: `GET/POST /api/evaluation-exceptions/`.
- **Primary integration target**: OrchestAI-style model orchestration platforms.

## Main Product Shape

AiSec now has two first-class surfaces:

1. **Integrated evaluator**: descriptor-in, deterministic evidence-out. This is
   the path for OrchestAI and other model orchestration platforms.
2. **Deep scanner**: Docker image-in, deep security report-out. This remains
   the path for containerized AI agents and runtime audits.

The integration boundary is JSON, not Python imports from the consuming
platform.

## What Was Completed In The Current v1.10.0 Workspace

### Developer Experience, Audit Trail, And API Maturity

New/updated capabilities:

- Decomposed `aisec serve` into `src/aisec/api/`.
- Added API auth, throttling, middleware, serializers, views, URL routing,
  scan runner, OpenAPI schema, Swagger UI, health probes, and WSGI factory.
- Added `AuditLogger` and `audit_events` SQLite table.
- Added `scan list`, `scan show`, `scan compare`, and `scan export`.
- Added `agents list` and `agents info`.
- Added CSV and Markdown renderers.
- Implemented `report convert`.
- Added pagination envelope for API list endpoints.
- Kept backward-compatible imports in `src/aisec/cli/serve.py`.

Key files:

- `src/aisec/api/`
- `src/aisec/core/audit.py`
- `src/aisec/core/history.py`
- `src/aisec/cli/agents.py`
- `src/aisec/cli/scan.py`
- `src/aisec/cli/report.py`
- `src/aisec/reports/renderers/csv_renderer.py`
- `src/aisec/reports/renderers/md_renderer.py`

### Model-Risk Evaluation Foundation

New/updated capabilities:

- Added `ModelRiskEvaluationRequest` and `ModelRiskEvaluationResult`.
- Added deterministic `evaluate_model_risk()` evaluator.
- Added `aisec evaluate model`.
- Added `aisec evaluate schema`.
- Added JSON schemas under `docs/schemas/`.
- Added OrchestAI request/result examples.
- Added validated OrchestAI use-case fixtures for customer-support RAG and an
  MCP-enabled operations agent.
- Added subprocess adapter example.
- Added HTTP adapter example for `aisec serve`.
- Added reusable orchestrator adapter guide for non-OrchestAI integrations.
- Added managed deployment guide and aligned Compose/Kubernetes/Helm probes
  with current service endpoints.
- Added managed API smoke script for pilot deployments.
- Added managed evidence capture script and rollback runbook for pilot
  operations.
- Added GitHub Actions and GitLab CI model-risk examples.
- Added `aisec evaluate summarize` for Markdown/JSON CI artifact summaries.
- Added `aisec evaluate evidence` for framework-grouped compliance evidence.
- Added `aisec evaluate compare` for current-versus-approved baseline
  comparisons.
- Added persisted API-mode model-risk evaluation history.
- Added API-mode approved baseline library and baseline comparison endpoint.
- Added API-mode evaluation rollup for governance/posture screens.
- Added API-mode accepted exceptions for model-risk finding fingerprints.
- Fixed API schema/health initialization under real DRF installs.
- Fixed lazy URL pattern reversibility for Django URL reversing.
- Fixed OpenAPI generation dependencies and route base path so schema exposes
  `/api/...` endpoints instead of `/api/api/...`.
- Added DRF `APIClient` end-to-end coverage for model-risk evaluation history,
  rollup, approved baseline creation, baseline comparison, accepted
  exceptions, and deletion.
- Added DRF `APIClient` negative-path coverage for missing evaluations,
  missing baselines, invalid baseline creation bodies, and invalid comparison
  bodies.
- Local `.venv` is installed with `.[api,dev]`; editable import and
  `.venv/bin/aisec` work without `PYTHONPATH`.
- Documented advisory and blocking CI modes.

Key files:

- `src/aisec/evaluation/models.py`
- `src/aisec/evaluation/evaluator.py`
- `src/aisec/cli/evaluate.py`
- `docs/orchestai-integration-protocol.md`
- `docs/examples/orchestai-model-risk-request.json`
- `docs/examples/orchestai-model-risk-result.json`
- `docs/examples/aisec_subprocess_adapter.py`
- `docs/examples/aisec_http_adapter.py`
- `docs/examples/github-actions-model-risk.yml`
- `docs/examples/gitlab-model-risk.yml`
- `src/aisec/evaluation/artifacts.py`

Important behavior:

- For the same request JSON, result IDs and timestamps are deterministic.
- `context.metadata.evaluation_created_at` or `context.metadata.created_at`
  can set the deterministic timestamp.
- Exit code `1` can mean policy failure with a valid result JSON. Integrators
  should still parse and store the result.

### Agent-On-Agent Analysis

New agent:

- `agentic_review`.

File:

- `src/aisec/agents/agentic_review.py`

Registered in:

- `src/aisec/agents/registry.py`

CLI discovery:

```bash
.venv/bin/aisec agents info agentic_review
```

`agentic_review` detects:

- self-review without independent reviewer boundary;
- recursive delegation without depth or budget guard;
- role prompts without explicit policy boundary;
- review decisions without audit trail or rationale evidence;
- quorum/consensus review without model/provider diversity;
- agent output reused as downstream instructions without sanitization;
- reviewer agents sharing privileged executor tools;
- shared agent identities or credentials;
- high-impact autonomous actions without human escalation;
- shared mutable memory between executor and reviewer agents;
- suppressed review dissent.

### Correlation Growth

Total correlation rules:

- `40`.

Rules centered on `agentic_review`:

1. `Unbounded Agent Delegation + Dangerous Tools = Autonomous Tool Abuse`
2. `Self-Review + Memory Risk = Persistent Agent Misjudgment`
3. `Unaudited Agent Review + Cascade Risk = Untraceable Multi-Agent Failure`
4. `Agent Handoff Injection + Weak Prompt Defenses = Cross-Agent Prompt Injection`
5. `Reviewer Tool Sharing + Tool Chain Risk = Compromised Control Plane`
6. `Shared Agent Identity + Exposed Credentials = Unattributable Agent Compromise`
7. `High-Impact Agent Action + Privileged Runtime = Unchecked Production Change`
8. `Shared Review Memory + Memory Risk = Biased Agent Oversight`
9. `Suppressed Review Dissent + Cascade Risk = Silent Multi-Agent Failure`

Key file:

- `src/aisec/core/correlation.py`

## Documentation For Another Agent

Primary handoff:

- `docs/AGENT_HANDOFF.md`

Read in this order:

1. `README.md`
2. `docs/INDEX.md`
3. `docs/AGENT_HANDOFF.md`
4. `docs/quickstart.md`
5. `docs/orchestai-integration-protocol.md`
6. `docs/architecture.md`
7. `docs/agents.md`
8. `docs/frameworks.md`

## Tests To Run

Full unit suite:

```bash
.venv/bin/python -m pytest tests/unit/ -q
```

Model-risk:

```bash
.venv/bin/python -m pytest tests/unit/test_model_risk_evaluation.py -q
```

Agent-on-agent analysis:

```bash
.venv/bin/python -m pytest \
  tests/unit/agents/test_agentic_review_agent.py \
  tests/unit/test_agentic_review_correlation.py \
  -q
```

Adapter and CI examples:

```bash
.venv/bin/python -m pytest \
  tests/unit/test_orchestrator_subprocess_adapter.py \
  tests/unit/test_ci_model_risk_examples.py \
  -q
```

## Current Iteration Notes

- The v1.10.0 release is already published.
- Duplicate untracked test files ending in ` 2.py` were compared against their
  canonical counterparts and removed before release.
- Service-to-service model-risk evaluation now has an API endpoint and a
  standalone HTTP adapter example.

## Key Decisions

- AiSec is integrated out-of-process by default.
- JSON request/result schemas are the compatibility boundary.
- Missing AiSec binary and timeout are optional evaluator failures, not
  platform failures.
- Evaluation output must remain deterministic for artifact comparison.
- `agentic_review` performs local meta-agent checks; `correlation.py` raises
  severity when meta-agent issues combine with tool, memory, cascade,
  permission, prompt, or credential risks.
- The deep scanner remains additive and should not be required for the
  model-risk evaluator.
