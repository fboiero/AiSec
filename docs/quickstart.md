# Quick Start

For a complete current-state handoff for another coding agent or downstream
integrator, start with [Agent Handoff](AGENT_HANDOFF.md).

## Install

```bash
pip install aisec
```

For all optional scan integrations:

```bash
pip install "aisec[all]"
```

From source:

```bash
git clone https://github.com/fboiero/AiSec.git
cd AiSec
pip install -e ".[dev]"
```

## 1. Evaluate A Model Or RAG Pipeline

Use this mode when integrating AiSec with OrchestAI or another model
orchestrator.

```bash
aisec evaluate model \
  --input docs/examples/orchestai-model-risk-request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical
```

Non-blocking evidence mode:

```bash
aisec evaluate model \
  --input request.json \
  --output result.json \
  --fail-on none
```

The result includes risk score, findings, framework mappings, evidence,
recommendations, and a policy verdict.

Create a Markdown summary from CI artifacts:

```bash
aisec evaluate summarize \
  --input aisec-results \
  --output aisec-results/model-risk-summary.md \
  --format markdown
```

Export framework-specific evidence for audit/compliance:

```bash
aisec evaluate evidence \
  --input aisec-results \
  --output aisec-results/model-risk-framework-evidence.md \
  --format markdown \
  --framework gdpr
```

Compare a current result against an approved baseline:

```bash
aisec evaluate compare \
  --baseline approved/model-risk-result.json \
  --current aisec-results/model-risk-result.json \
  --output aisec-results/model-risk-comparison.md \
  --format markdown
```

CI advisory mode uses `--fail-on none` and always uploads the JSON result as
evidence. CI blocking mode uses `--fail-on critical` or `--fail-on high`; the
command exits with code `1` when the policy verdict is `fail`. CI examples
upload raw JSON evidence, the Markdown summary, and a baseline comparison when
an approved baseline artifact exists.

Export JSON Schemas for adapter validation:

```bash
aisec evaluate schema --output-dir docs/schemas
```

Try additional target examples:

```bash
aisec evaluate model --input docs/examples/model-route-risk-request.json --output /tmp/model-route-result.json
aisec evaluate model --input docs/examples/tool-agent-risk-request.json --output /tmp/tool-agent-result.json
aisec evaluate model --input docs/examples/mcp-workflow-risk-request.json --output /tmp/mcp-workflow-result.json
```

Copyable CI examples:

- [GitHub Actions model-risk gate](examples/github-actions-model-risk.yml)
- [GitLab CI model-risk gate](examples/gitlab-model-risk.yml)

## 2. Scan A Dockerized AI Agent

Use this mode for deep audits of a running/containerized agent.

```bash
aisec scan run myagent:latest --format json,html,sarif
```

Run selected agents:

```bash
aisec scan run myagent:latest \
  --agents rag_security,mcp_security,tool_chain,privacy
```

Spanish reports:

```bash
aisec scan run myagent:latest --lang es
```

## 3. Start API And Dashboard

```bash
aisec serve --port 8000
```

Open:

```text
http://localhost:8000/dashboard/
http://localhost:8000/api/docs/
```

Model-risk API mode:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  --data @docs/examples/orchestai-model-risk-request.json \
  http://localhost:8000/api/evaluate/model/
```

Persisted evaluation history:

```text
http://localhost:8000/api/evaluations/
http://localhost:8000/api/evaluations/rollup/
http://localhost:8000/api/evaluations/{evaluation_id}/
```

Approved model-risk baselines:

```text
http://localhost:8000/api/evaluation-baselines/
http://localhost:8000/api/evaluation-baselines/{baseline_id}/compare/
```

Accepted model-risk exceptions:

```text
http://localhost:8000/api/evaluation-exceptions/
http://localhost:8000/api/evaluation-exceptions/{exception_id}/
```

Create exceptions from comparison `new_findings[].fingerprint` values. Active,
non-expired exceptions are applied automatically by baseline comparison and move
matching new findings into `accepted_new_findings`.

## 4. Understand Results

AiSec findings include:

- Severity: `critical`, `high`, `medium`, `low`, `info`.
- Framework mappings: OWASP LLM, OWASP Agentic, NIST AI RMF, ISO 42001,
  GDPR, Habeas Data, and others.
- Evidence.
- Remediation.
- Policy verdict.

## 5. Integrate With OrchestAI

Recommended flow:

```text
OrchestAI compliance evaluator
  -> builds ModelRiskEvaluationRequest
  -> invokes aisec evaluate model
  -> parses ModelRiskEvaluationResult
  -> stores result as compliance evidence
```

Read:

- [OrchestAI Integration Protocol](orchestai-integration-protocol.md)
- [Architecture](architecture.md)
- [Frameworks](frameworks.md)
