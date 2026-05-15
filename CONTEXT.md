# AiSec Session Context

## Current State

- **Version**: `1.10.0` local.
- **Branch**: `main`.
- **Release target**: `v1.10.0`.
- **Unit tests**: `1430 passed, 14 skipped`.
- **Security agents**: `36`.
- **Correlation rules**: `40`.
- **Agent-on-agent correlation rules**: `9`.
- **Model-risk protocol**: `aisec.model_risk.v1`.
- **Primary evaluator command**: `aisec evaluate model`.
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
- Added subprocess adapter example.
- Added GitHub Actions and GitLab CI model-risk examples.
- Documented advisory and blocking CI modes.

Key files:

- `src/aisec/evaluation/models.py`
- `src/aisec/evaluation/evaluator.py`
- `src/aisec/cli/evaluate.py`
- `docs/orchestai-integration-protocol.md`
- `docs/examples/orchestai-model-risk-request.json`
- `docs/examples/orchestai-model-risk-result.json`
- `docs/examples/aisec_subprocess_adapter.py`
- `docs/examples/github-actions-model-risk.yml`
- `docs/examples/gitlab-model-risk.yml`

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
PYTHONPATH=src python3 -m aisec agents info agentic_review
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
PYTHONPATH=src python3 -m pytest tests/unit/ -q
```

Model-risk:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_model_risk_evaluation.py -q
```

Agent-on-agent analysis:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/unit/agents/test_agentic_review_agent.py \
  tests/unit/test_agentic_review_correlation.py \
  -q
```

Adapter and CI examples:

```bash
PYTHONPATH=src python3 -m pytest \
  tests/unit/test_orchestrator_subprocess_adapter.py \
  tests/unit/test_ci_model_risk_examples.py \
  -q
```

## Known Pending Cleanup

- Duplicate untracked test files ending in ` 2.py` were compared against their
  canonical counterparts and removed.
- Review all untracked files before commit because this workspace contains many
  newly created source, docs, and test files.
- Commit, tag, push, and create the v1.10.0 release after a final full test run.

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
