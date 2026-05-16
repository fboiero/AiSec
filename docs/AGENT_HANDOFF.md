# AiSec Agent Handoff

This document is the handoff for another engineer or coding agent integrating
AiSec from another repository.

It is intentionally operational: read this first, then follow the linked docs
for deeper reference.

## Current State

As of the current local workspace:

- Version: `1.10.0`.
- Branch: `main`.
- Release target: `v1.10.0`.
- Unit tests: `1484 passed, 9 skipped` in local `.venv` with `.[api,dev]`.
- Security agents: `36`.
- Correlation rules: `40`.
- Agent-on-agent correlation rules: `9`.
- Model-risk schema version: `aisec.model_risk.v1`.
- Primary integration command: `aisec evaluate model`.
- Primary integration API: `POST /api/evaluate/model/`.
- Primary integration target: OrchestAI-style model orchestration platforms.

Important workspace note:

- Duplicate untracked test files ending in ` 2.py` were verified as
  byte-for-byte copies and removed before release preparation.

## Product Summary

AiSec has two complementary surfaces:

1. **Integrated evaluator**: a descriptor-based model-risk evaluator that
   orchestration platforms can call without importing AiSec internals.
2. **Deep scanner**: a Docker-based scanner for agentic applications and AI
   systems.

The evaluator is the integration surface for OrchestAI and similar products.
The scanner is the deeper audit surface for containerized agents.

## Integration Principle

Do not couple the consuming platform to AiSec Python internals.

The recommended boundary is:

```text
consuming platform
  -> build ModelRiskEvaluationRequest JSON
  -> call AiSec by CLI, container, or API
  -> parse ModelRiskEvaluationResult JSON
  -> store result as immutable compliance evidence
```

Suggested adapter path in a consuming backend:

```text
backend/app/services/compliance/evaluators/aisec.py
```

## Fast Path For Another Project

### 1. Install AiSec

```bash
pip install aisec
```

From this source checkout:

```bash
pip install -e ".[dev]"
```

### 2. Create A Request

Start from:

```text
docs/examples/orchestai-model-risk-request.json
docs/examples/orchestai-usecase-customer-support-rag.json
docs/examples/orchestai-usecase-ops-agent-mcp.json
```

Other request profiles:

```text
docs/examples/model-route-risk-request.json
docs/examples/tool-agent-risk-request.json
docs/examples/mcp-workflow-risk-request.json
```

### 3. Run The Evaluator

Advisory mode:

```bash
aisec evaluate model \
  --input request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on none \
  --quiet
```

Blocking mode:

```bash
aisec evaluate model \
  --input request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical \
  --quiet
```

Exit codes:

- `0`: `policy_verdict.status` is `pass` or `warn`.
- `1`: `policy_verdict.status` is `fail`.

Important: exit code `1` can still be a successful evaluator invocation. If the
result JSON exists, parse and store it. The platform decides whether to block.

### 4. Store Evidence

Store the full result JSON. Index at least:

- `evaluation_id`
- `request_id`
- `schema_version`
- `target.type`
- `target.name`
- `target.provider`
- `target.model_id`
- `overall_risk`
- `risk_score`
- `policy_verdict.status`
- finding severities
- mapped frameworks

## Request Contract

Python model:

```text
src/aisec/evaluation/models.py::ModelRiskEvaluationRequest
```

Schema:

```text
docs/schemas/model-risk-request.schema.json
```

Required conceptual fields:

- `schema_version`: currently `aisec.model_risk.v1`.
- `request_id`: stable ID from the consuming platform.
- `source`: platform name, for example `orchestai`.
- `target`: model, agent, RAG pipeline, or workflow descriptor.
- `frameworks`: frameworks requested for mapping.
- `context`: organization/project/jurisdiction/safeguards metadata.
- `policy`: gate configuration such as `fail_on`.

Target types:

- `model`
- `agent`
- `rag_pipeline`
- `workflow`

Capabilities:

- `rag_enabled`
- `tools_enabled`
- `memory_enabled`
- `mcp_enabled`
- `code_execution_enabled`
- `web_access_enabled`
- `fine_tuning_enabled`
- `multimodal_enabled`

Safeguards:

- `pii_redaction`
- `prompt_logging_disabled`
- `consent_required`
- `retention_policy_defined`
- `human_in_loop`
- `tool_approval_required`
- `output_filtering`
- `retrieval_filtering`
- `tenant_isolation`
- `audit_logging`
- `rate_limiting`

## Result Contract

Python model:

```text
src/aisec/evaluation/models.py::ModelRiskEvaluationResult
```

Schema:

```text
docs/schemas/model-risk-result.schema.json
```

Result includes:

- `schema_version`
- `evaluation_id`
- `request_id`
- `engine`
- `engine_version`
- `created_at`
- `target`
- `overall_risk`
- `risk_score`
- `frameworks`
- `findings`
- `evidence`
- `recommendations`
- `policy_verdict`
- `metadata`

All findings must include:

- severity
- framework mapping
- evidence
- remediation

## Deterministic Output

For the same request JSON, AiSec emits stable result, finding, and evidence IDs.

`created_at` is deterministic too:

- If `context.metadata.evaluation_created_at` is present, AiSec uses it.
- Else if `context.metadata.created_at` is present, AiSec uses it.
- Otherwise AiSec uses a stable default timestamp.

This lets CI jobs and orchestrator adapters compare result artifacts across
runs.

## Optional Evaluator Failure Handling

AiSec should not be a hard dependency for platform availability.

Use:

```text
docs/examples/aisec_subprocess_adapter.py
```

The adapter treats:

- missing `aisec` binary as `available=False`;
- timeout as `timed_out=True`;
- exit code `1` with a valid result JSON as a successful evaluation with a
  failing policy verdict;
- non-zero exit without a result JSON as evaluator failure, not platform
  failure.

## CI Examples

Copy these into a consuming repository:

```text
docs/examples/github-actions-model-risk.yml
docs/examples/gitlab-model-risk.yml
```

Recommended rollout:

1. Advisory mode: `--fail-on none`, upload JSON artifact.
2. Blocking mode for protected branches: start with `--fail-on critical`.
3. Tighten to `--fail-on high` after teams agree on accepted-exception
   ownership and expiry policy.

## Deep Scan Path

Use this when the target is a Dockerized AI agent:

```bash
aisec scan run myagent:latest --format json,html,sarif,csv,md
aisec scan run myagent:latest --agents rag_security,mcp_security,tool_chain
aisec scan run myagent:latest --policy strict --gate
```

Deep scans use:

- Docker sandboxing in `src/aisec/docker_/`;
- DAG execution in `src/aisec/agents/orchestrator.py`;
- built-in agents in `src/aisec/agents/`;
- report building in `src/aisec/reports/`;
- policy gates in `src/aisec/policies/`;
- correlation rules in `src/aisec/core/correlation.py`.

## Current Agent Landscape

There are `36` registered agents.

Core families:

- network exposure
- data flow and privacy
- prompt security
- supply chain
- permissions and excessive agency
- output safety
- cryptography
- SBOM
- Garak/adversarial testing
- guardrails
- model scanning
- cascade and inter-agent analysis
- RAG
- MCP
- tool-chain security
- agent memory
- fine-tuning
- CI/CD
- Falco runtime
- agentic review

New agent-on-agent analysis:

```text
src/aisec/agents/agentic_review.py
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

Framework mappings:

- OWASP Agentic: `ASI02`, `ASI03`, `ASI08`.
- NIST AI RMF: `GOVERN`, `MANAGE`, `MEASURE` depending on finding.

## Correlation Rules

There are `40` correlation rules.

Nine rules are centered on `agentic_review`:

1. `Unbounded Agent Delegation + Dangerous Tools = Autonomous Tool Abuse`
2. `Self-Review + Memory Risk = Persistent Agent Misjudgment`
3. `Unaudited Agent Review + Cascade Risk = Untraceable Multi-Agent Failure`
4. `Agent Handoff Injection + Weak Prompt Defenses = Cross-Agent Prompt Injection`
5. `Reviewer Tool Sharing + Tool Chain Risk = Compromised Control Plane`
6. `Shared Agent Identity + Exposed Credentials = Unattributable Agent Compromise`
7. `High-Impact Agent Action + Privileged Runtime = Unchecked Production Change`
8. `Shared Review Memory + Memory Risk = Biased Agent Oversight`
9. `Suppressed Review Dissent + Cascade Risk = Silent Multi-Agent Failure`

The key design decision: `agentic_review` finds local meta-agent design issues,
while `correlation.py` elevates risk when those issues combine with
`tool_chain`, `agent_memory`, `cascade`, `prompt_security`, `dataflow`, or
`permission` findings.

## API And Dashboard

Run:

```bash
aisec serve --port 8000
```

Important paths:

- Dashboard: `/dashboard/`
- OpenAPI UI: `/api/docs/`
- OpenAPI JSON: `/api/schema/`
- Readiness: `/api/ready/`
- Liveness: `/api/live/`

API implementation:

```text
src/aisec/api/
```

Dashboard implementation:

```text
src/aisec/dashboard/
```

## Persistence And Audit

Scan history and audit events live in SQLite via:

```text
src/aisec/core/history.py
src/aisec/core/audit.py
```

Audit events are co-located with scan history in the same local history DB.

## Reports

Formats:

- JSON
- HTML
- PDF
- SARIF
- CSV
- Markdown

Renderers:

```text
src/aisec/reports/renderers/
```

New renderers:

```text
src/aisec/reports/renderers/csv_renderer.py
src/aisec/reports/renderers/md_renderer.py
```

## Plugin Boundary

Plugin hooks are in:

```text
src/aisec/plugins/
```

Agent orchestration calls plugin hooks:

- `pre_scan`
- `on_finding`
- `post_scan`
- `modify_report`

Hook failures are isolated and should not crash scans.

## Important Commands

Run all unit tests:

```bash
.venv/bin/python -m pytest tests/unit/ -q
```

Run model-risk tests:

```bash
.venv/bin/python -m pytest tests/unit/test_model_risk_evaluation.py -q
```

Run agentic review tests:

```bash
.venv/bin/python -m pytest \
  tests/unit/agents/test_agentic_review_agent.py \
  tests/unit/test_agentic_review_correlation.py \
  -q
```

Export schemas:

```bash
.venv/bin/aisec evaluate schema --output-dir docs/schemas
```

Smoke the OrchestAI example:

```bash
.venv/bin/aisec evaluate model \
  --input docs/examples/orchestai-model-risk-request.json \
  --output /tmp/aisec-model-risk-result.json \
  --fail-on none \
  --quiet
```

List agents:

```bash
.venv/bin/aisec agents list
.venv/bin/aisec agents info agentic_review
```

## Key Files For Integrators

Read in this order:

1. `README.md`
2. `docs/INDEX.md`
3. `docs/quickstart.md`
4. `docs/orchestai-integration-protocol.md`
5. `docs/architecture.md`
6. `docs/agents.md`
7. `docs/frameworks.md`
8. `docs/examples/aisec_subprocess_adapter.py`

Code entry points:

```text
src/aisec/cli/app.py
src/aisec/cli/evaluate.py
src/aisec/api/views.py
src/aisec/api/urls.py
src/aisec/evaluation/models.py
src/aisec/evaluation/evaluator.py
src/aisec/agents/registry.py
src/aisec/agents/agentic_review.py
src/aisec/core/correlation.py
```

## Release Preparation Notes

Release-prep cleanup performed:

- Duplicate untracked test files ending in ` 2.py` were removed.
- Full unit suite was re-run after cleanup.

Operational release steps:

- Commit this workspace as the v1.10.0 release commit.
- Tag the commit as `v1.10.0`.
- Push `main` and the tag.
- Create the GitHub release from `CHANGELOG.md`.

Next product iterations:

- Baseline promotion workflow in OrchestAI UI.

Completed after v1.10.0 release:

- Added service-to-service model-risk endpoint:
  `POST /api/evaluate/model/`.
- Added standalone HTTP adapter example:
  `docs/examples/aisec_http_adapter.py`.
- Added reusable orchestrator adapter guide:
  `docs/orchestrator-adapter-guide.md`.
- Added managed deployment guide:
  `docs/managed-deployment.md`.
- Added managed API smoke script:
  `scripts/smoke-managed-api.sh`.
- Added managed evidence capture script and rollback runbook:
  `scripts/capture-managed-evidence.sh`.
- Added validated OrchestAI use-case fixtures for customer-support RAG and an
  MCP-enabled operations agent.
- Added CI artifact parser and summary command:
  `aisec evaluate summarize`.
- Added framework evidence export command:
  `aisec evaluate evidence`.
- Added baseline comparison command for approved model-risk evidence:
  `aisec evaluate compare`.
- Added API-mode evaluation history:
  `GET /api/evaluations/` and `GET /api/evaluations/{evaluation_id}/`.
- Added governance rollup endpoint:
  `GET /api/evaluations/rollup/`.
- Added approved model-risk baseline library:
  `GET/POST /api/evaluation-baselines/` and
  `POST /api/evaluation-baselines/{baseline_id}/compare/`.
- Added accepted model-risk exceptions:
  `GET/POST /api/evaluation-exceptions/` and
  `DELETE /api/evaluation-exceptions/{exception_id}/`.
- Exception acceptance is scoped by `target_name` and finding fingerprint;
  `expires_at` is honored when active exceptions are listed or applied.
- Baseline comparison now separates `accepted_new_findings` and
  `unaccepted_new_findings`; `has_regression` means an unaccepted regression
  remains, while `risk_regressed` and `policy_regressed` stay visible as
  posture signals.
- Local `.venv` is installed with `.[api,dev]`; `.venv/bin/python` imports
  `aisec` and `.venv/bin/aisec` works without `PYTHONPATH`.
- OpenAPI generation is validated with real DRF dependencies and should expose
  `/api/...` paths, not `/api/api/...`.
- DRF `APIClient` end-to-end tests cover model-risk evaluation, history,
  rollup, approved baselines, accepted exceptions, comparison, and deletion.
- DRF `APIClient` negative-path tests cover missing evaluations, missing
  baselines, invalid baseline bodies, and invalid comparison bodies.

## Invariants For Future Agents

- Keep the evaluator contract stable across minor versions.
- Add fields as optional rather than breaking existing JSON.
- Do not make OrchestAI import AiSec internals.
- Keep `aisec evaluate model` deterministic for the same request JSON.
- Every finding must include evidence and remediation.
- Framework mappings must remain explicit.
- Deep scan functionality must remain additive, not required for the evaluator.
