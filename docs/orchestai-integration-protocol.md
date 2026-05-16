# AiSec Orchestrator Integration Protocol

## Purpose

This protocol lets OrchestAI and similar model orchestrators use AiSec as an
optional compliance and AI-security evaluation engine for models, agents, RAG
pipelines, and workflows.

For a full current-state handoff aimed at another coding agent, read
[`AGENT_HANDOFF.md`](AGENT_HANDOFF.md).

AiSec is not imported into the orchestrator as an application dependency. The
orchestrator invokes AiSec through a stable JSON contract, initially via
CLI/container or through the same payload over the `aisec serve` API.

```text
Orchestrator compliance module
  -> writes model-risk request JSON
  -> calls aisec evaluate model --input request.json --output result.json
  -> stores result.json as model risk evidence
```

## Contract Version

Current schema version:

```text
aisec.model_risk.v1
```

Both request and result include `schema_version`. Consumers should reject
unknown major versions and treat new optional fields as backward-compatible.

JSON Schemas:

- [`schemas/model-risk-request.schema.json`](schemas/model-risk-request.schema.json)
- [`schemas/model-risk-result.schema.json`](schemas/model-risk-result.schema.json)

Export them from source:

```bash
aisec evaluate schema --output-dir docs/schemas
```

## CLI Invocation

```bash
aisec evaluate model \
  --input orchestai-model-risk-request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical
```

Exit codes:

- `0`: policy verdict is `pass` or `warn`.
- `1`: policy verdict is `fail`.

Use `--fail-on none` for non-blocking evidence collection.

Summarize one or more result artifacts for PR/MR comments or CI uploads:

```bash
aisec evaluate summarize \
  --input aisec-results \
  --output aisec-results/model-risk-summary.md \
  --format markdown \
  --no-strict
```

The summary command accepts JSON files or directories, validates
`ModelRiskEvaluationResult` artifacts, and writes a compact rollup with target,
risk, verdict, severity counts, and top findings.

Compare a current result against an approved baseline:

```bash
aisec evaluate compare \
  --baseline approved/model-risk-result.json \
  --current aisec-results/model-risk-result.json \
  --output aisec-results/model-risk-comparison.md \
  --format markdown
```

Use `--fail-on-regression` when CI should block on unaccepted new findings,
worse risk level, or worse policy verdict. In API mode, active model-risk
exceptions can accept specific new finding fingerprints for a target.

Other examples:

- [`examples/aisec_subprocess_adapter.py`](examples/aisec_subprocess_adapter.py)
- [`examples/aisec_http_adapter.py`](examples/aisec_http_adapter.py)
- [`examples/github-actions-model-risk.yml`](examples/github-actions-model-risk.yml)
- [`examples/gitlab-model-risk.yml`](examples/gitlab-model-risk.yml)
- [`examples/model-route-risk-request.json`](examples/model-route-risk-request.json)
- [`examples/orchestai-model-risk-request.json`](examples/orchestai-model-risk-request.json)
- [`examples/orchestai-model-risk-result.json`](examples/orchestai-model-risk-result.json)
- [`examples/tool-agent-risk-request.json`](examples/tool-agent-risk-request.json)
- [`examples/mcp-workflow-risk-request.json`](examples/mcp-workflow-risk-request.json)

## Request Shape

Minimal request:

```json
{
  "schema_version": "aisec.model_risk.v1",
  "source": "orchestai",
  "target": {
    "type": "rag_pipeline",
    "name": "EPEC claims assistant",
    "provider": "openai",
    "model_id": "gpt-4.1",
    "environment": "staging",
    "usage_context": "customer-support-rag",
    "capabilities": {
      "rag_enabled": true,
      "tools_enabled": true,
      "memory_enabled": false,
      "mcp_enabled": false,
      "code_execution_enabled": false
    },
    "data_classes": ["pii", "customer_messages", "internal_docs"]
  },
  "frameworks": [
    "owasp_llm",
    "owasp_agentic",
    "nist_ai_rmf",
    "nist_ai_600_1",
    "iso_42001",
    "gdpr",
    "habeas_data"
  ],
  "context": {
    "organization_id": "xcapit",
    "project_id": "orchestai-epec",
    "jurisdiction": "AR",
    "safeguards": {
      "pii_redaction": true,
      "prompt_logging_disabled": true,
      "consent_required": true,
      "retention_policy_defined": true,
      "human_in_loop": true,
      "tool_approval_required": true,
      "output_filtering": true,
      "retrieval_filtering": true,
      "tenant_isolation": true,
      "audit_logging": true,
      "rate_limiting": true
    }
  },
  "policy": {
    "fail_on": "critical"
  }
}
```

## Result Shape

AiSec returns:

- `overall_risk`: `critical`, `high`, `medium`, `low`, or `info`.
- `risk_score`: numeric score from `0.0` to `10.0`.
- `findings`: normalized findings with severity, framework mapping, evidence,
  and remediation.
- `frameworks`: framework-level status rollups.
- `policy_verdict`: `pass`, `warn`, or `fail`.
- `evidence`: evaluation-level evidence.

The consuming platform should store the full JSON result as immutable compliance
evidence and index at least:

- `evaluation_id`
- `request_id`
- `target.name`
- `target.model_id`
- `overall_risk`
- `risk_score`
- `policy_verdict.status`
- finding severities
- mapped frameworks

## Deterministic Output

For the same request JSON, AiSec emits stable result, finding, and evidence IDs
so CI jobs and orchestrator adapters can compare artifacts across runs. The
result `created_at` value is read from `context.metadata.evaluation_created_at`
or `context.metadata.created_at` when provided. If neither field is present,
AiSec uses a stable default timestamp to keep output reproducible.

## Recommended Adapter

Suggested backend boundary for OrchestAI:

```text
backend/app/services/compliance/evaluators/aisec.py
```

Generic adapter responsibilities:

1. Build `ModelRiskEvaluationRequest` from model/provider/workflow
   configuration.
2. Execute AiSec through CLI, container, or API.
3. Parse and validate `ModelRiskEvaluationResult`.
4. Store the result as compliance evidence.
5. Surface summary fields in the model compliance UI.

The adapter should be optional and controlled by tenant/project settings:

```yaml
compliance:
  evaluators:
    aisec:
      enabled: true
      mode: cli
      fail_on: critical
      timeout_seconds: 600
```

## HTTP Invocation

When AiSec is running as a service, submit the same request payload to:

```http
POST /api/evaluate/model/
Content-Type: application/json
Accept: application/json
```

Start a local API server:

```bash
aisec serve --host 127.0.0.1 --port 8000
```

Then call:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  --data @docs/examples/orchestai-model-risk-request.json \
  http://127.0.0.1:8000/api/evaluate/model/
```

The response body is the same `ModelRiskEvaluationResult` returned by the CLI.
The HTTP endpoint does not turn policy failures into HTTP errors; a valid
evaluation returns `200` and the consuming platform should inspect
`policy_verdict.status`.

API-mode evaluations are persisted as evidence records. Retrieve them with:

```http
GET /api/evaluations/
GET /api/evaluations/rollup/
GET /api/evaluations/{evaluation_id}/
```

`GET /api/evaluations/` returns a paginated summary list and accepts optional
`target_name`, `page`, and `page_size` query parameters. The detail endpoint
returns the stored request and full result JSON. The rollup endpoint returns
posture metrics for governance screens: total evaluations, unique targets,
average risk score, risk counts, policy verdict counts, and latest evaluations.

Approved baselines can be stored from persisted evaluations:

```http
POST /api/evaluation-baselines/
GET /api/evaluation-baselines/
GET /api/evaluation-baselines/{baseline_id}/
DELETE /api/evaluation-baselines/{baseline_id}/
POST /api/evaluation-baselines/{baseline_id}/compare/
```

Baseline creation body:

```json
{
  "name": "release-approved",
  "target_name": "EPEC claims assistant",
  "evaluation_id": "stored-evaluation-id",
  "description": "Approved release evidence"
}
```

Baseline comparison body:

```json
{
  "current_evaluation_id": "current-evaluation-id"
}
```

The comparison response includes `new_findings`, `accepted_new_findings`,
`unaccepted_new_findings`, `resolved_findings`, `unchanged_findings`,
`risk_regressed`, `policy_regressed`, and `has_regression`. `has_regression`
means there is an unaccepted regression that should block a gate.

Accepted exceptions are managed independently from baselines:

```http
POST /api/evaluation-exceptions/
GET /api/evaluation-exceptions/
DELETE /api/evaluation-exceptions/{exception_id}/
```

Exception creation body:

```json
{
  "target_name": "EPEC claims assistant",
  "finding_fingerprint": "finding-fingerprint-from-comparison",
  "reason": "Accepted for pilot window",
  "accepted_by": "security",
  "expires_at": "2026-06-30T23:59:59Z"
}
```

`GET /api/evaluation-exceptions/` accepts optional `target_name`. Baseline
comparison automatically applies active, non-expired exceptions for the current
evaluation's target. Deleting an exception deactivates it instead of removing
the audit record.

Use [`examples/aisec_http_adapter.py`](examples/aisec_http_adapter.py) for a
standalone Python client that distinguishes endpoint/network failures from
valid AiSec policy results.

The subprocess adapter example treats infrastructure failures separately from
AiSec policy results:

- Missing `aisec` binary: return an unavailable evaluator result and let the
  platform continue.
- Timeout: return a timed-out evaluator result and let the platform continue.
- Exit code `1` with a result JSON: parse and store the result; this usually
  means AiSec produced a `policy_verdict.status` of `fail`.
- Non-zero exit without result JSON: record the adapter error as evaluator
  failure, not as platform failure.

## Framework Mapping

Recommended baseline for OrchestAI:

| Framework | Why it matters |
| --- | --- |
| `owasp_llm` | Prompt injection, data disclosure, excessive agency, unbounded consumption |
| `owasp_agentic` | Tool misuse, identity abuse, memory poisoning, inter-agent risks |
| `nist_ai_rmf` | AI governance, measurement, and risk management |
| `nist_ai_600_1` | Generative AI profile evidence |
| `iso_42001` | AI management system controls |
| `gdpr` | Personal data processing and privacy controls |
| `habeas_data` | Argentina personal data obligations |

## Integration Phases

1. **Non-blocking evidence**: run with `--fail-on none`, store artifacts.
2. **MR advisory**: show risk summary in merge request comments or artifacts.
3. **Policy gate**: fail on `critical`, later on `high` for protected branches.
4. **Governance ingestion**: show AiSec evaluations inside OrchestAI compliance.
5. **Runtime extension**: combine descriptor evaluation with scan/runtime findings.

For CI adoption, start with advisory mode so the pipeline uploads
`aisec-results/model-risk-result.json` without blocking merges. Move protected
branches to blocking mode once teams agree on the threshold and exception flow.
