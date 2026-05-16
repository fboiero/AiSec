# AiSec Orchestrator Adapter Guide

This guide is for teams integrating AiSec into an AI orchestration platform,
model registry, workflow engine, agent runtime, or governance product.

Use the OrchestAI protocol as the concrete reference, but keep the adapter
generic: the consuming platform should build JSON, call AiSec out of process,
and store the returned JSON as evidence.

## Integration Boundary

Do not import AiSec Python internals from the consuming platform.

Recommended boundary:

```text
orchestrator domain model
  -> adapter maps platform fields to ModelRiskEvaluationRequest JSON
  -> adapter invokes AiSec by CLI, container, or HTTP API
  -> adapter validates ModelRiskEvaluationResult JSON
  -> platform stores result and derived artifacts as evidence
```

Contract files:

- [`schemas/model-risk-request.schema.json`](schemas/model-risk-request.schema.json)
- [`schemas/model-risk-result.schema.json`](schemas/model-risk-result.schema.json)
- [`orchestai-integration-protocol.md`](orchestai-integration-protocol.md)

## Adapter Responsibilities

The adapter should own five small tasks:

1. Map platform configuration into `ModelRiskEvaluationRequest`.
2. Select execution mode: CLI, container, or HTTP API.
3. Separate infrastructure errors from valid AiSec policy failures.
4. Store immutable result JSON plus optional summary/comparison artifacts.
5. Return concise fields to the platform UI and approval workflows.

Suggested adapter module paths:

```text
backend/app/services/compliance/evaluators/aisec.py
backend/app/integrations/aisec/client.py
backend/app/governance/evidence/aisec.py
```

## Field Mapping

Map platform concepts into the stable request contract:

| Platform concept | AiSec field |
| --- | --- |
| Application, workflow, route, agent, or model config ID | `request_id`, `target.metadata` |
| Model provider and model name | `target.provider`, `target.model_id` |
| Model, agent, RAG pipeline, or workflow type | `target.type` |
| Enabled runtime features | `target.capabilities` |
| Data categories handled by the use case | `target.data_classes` |
| Tenant, project, region, or jurisdiction | `context.organization_id`, `context.project_id`, `context.jurisdiction` |
| Existing controls | `context.safeguards` |
| CI or approval threshold | `policy.fail_on` |

Set `context.metadata.evaluation_created_at` when deterministic timestamps are
needed for fixtures, CI comparisons, or golden artifacts.

## Execution Modes

### CLI

Use the CLI when the consuming platform can run a local binary or containerized
job:

```bash
aisec evaluate model \
  --input request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical \
  --quiet
```

Exit code `1` with a valid result JSON is a successful evaluation with a
failing policy verdict. Treat it as governance data, not as adapter failure.

### HTTP API

Use HTTP when AiSec runs as a shared service:

```http
POST /api/evaluate/model/
Content-Type: application/json
Accept: application/json
```

The endpoint returns `200` for valid evaluations, including policy failures.
Inspect `policy_verdict.status` to decide whether the platform should block.

### Container

Use container execution when CI/CD should avoid installing AiSec directly. The
same CLI contract applies: mount request/output directories and collect the
JSON artifact.

## Error Handling

Handle outcomes explicitly:

| Outcome | Adapter behavior |
| --- | --- |
| AiSec unavailable or binary missing | Mark evaluator unavailable; do not fabricate risk. |
| Timeout | Mark evaluator timed out and include timeout metadata. |
| Invalid request JSON | Surface adapter/configuration error to the platform owner. |
| HTTP 4xx/5xx or network error | Mark infrastructure failure and retry according to platform policy. |
| Exit code `1` with result JSON | Store result; policy verdict is `fail`. |
| Valid result with `policy_verdict.status=warn` | Store result; usually advisory. |
| Valid result with `policy_verdict.status=pass` | Store result; no blocking findings. |

## Evidence To Store

Store the full `ModelRiskEvaluationResult` JSON as immutable evidence. Index:

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

Optional derived artifacts:

```bash
aisec evaluate summarize --input aisec-results --output aisec-results/model-risk-summary.md
aisec evaluate evidence --input aisec-results --output aisec-results/model-risk-framework-evidence.md
aisec evaluate compare --baseline approved/model-risk-result.json --current aisec-results/model-risk-result.json
```

## Baselines And Exceptions

For API-mode governance:

```http
GET /api/evaluations/
GET /api/evaluations/rollup/
POST /api/evaluation-baselines/
POST /api/evaluation-baselines/{baseline_id}/compare/
POST /api/evaluation-exceptions/
```

Use baselines for approved evidence snapshots. Use exceptions for accepted
finding fingerprints with explicit `reason`, `accepted_by`, and optional
`expires_at`.

`has_regression` in baseline comparison means an unaccepted regression remains.
`risk_regressed` and `policy_regressed` remain visible as posture signals.

## UI Fields

A compact UI can start with:

| Field | Source |
| --- | --- |
| Risk badge | `overall_risk` |
| Numeric score | `risk_score` |
| Gate result | `policy_verdict.status` |
| Finding count | `findings.length` |
| Framework cards | `frameworks[]` |
| Top remediations | `recommendations[]` |
| Evidence detail | `findings[].evidence[]` |

## Validation Checklist

Before shipping an adapter:

- Validate request/result JSON against the published schemas.
- Run at least one clean/advisory case and one blocking case.
- Store the full result JSON even when policy verdict is `fail`.
- Preserve AiSec `evaluation_id` and platform `request_id`.
- Confirm deterministic outputs for fixed `request_id` and timestamp metadata.
- Exercise timeout, unavailable binary/service, invalid JSON, and policy failure.
- Decide whether CI runs advisory, blocking, or baseline-regression mode.

Reference examples:

- [`examples/aisec_subprocess_adapter.py`](examples/aisec_subprocess_adapter.py)
- [`examples/aisec_http_adapter.py`](examples/aisec_http_adapter.py)
- [`examples/orchestai-usecase-customer-support-rag.json`](examples/orchestai-usecase-customer-support-rag.json)
- [`examples/orchestai-usecase-ops-agent-mcp.json`](examples/orchestai-usecase-ops-agent-mcp.json)
