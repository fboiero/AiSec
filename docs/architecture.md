# AiSec Architecture

## Overview

AiSec has two execution paths:

1. **Evaluation path**: descriptor-in, evidence-out. This is the primary path
   for OrchestAI and similar platforms.
2. **Scan path**: Docker image-in, deep security report-out. This remains the
   path for agent/container audits.

Both paths produce normalized findings that can be stored, rendered, compared,
or used by policy gates.

For external coding agents and downstream integrators, the canonical current
state is documented in [Agent Handoff](AGENT_HANDOFF.md). Read that document
before modifying integration code.

## Evaluation Path

```text
Model orchestrator
  -> ModelRiskEvaluationRequest JSON
  -> aisec evaluate model
  -> descriptor evaluator
  -> framework mapper
  -> policy verdict
  -> ModelRiskEvaluationResult JSON
```

Key modules:

- `src/aisec/evaluation/models.py`: request/result protocol.
- `src/aisec/evaluation/evaluator.py`: descriptor-based risk evaluator.
- `src/aisec/cli/evaluate.py`: CLI integration surface.

This path is intentionally lightweight. It does not require Docker and does not
import the consuming platform's code. The platform supplies the target
descriptor: model, provider, usage context, capabilities, data classes, and
safeguards.

## Scan Path

```text
aisec scan run <image>
  -> Load config
  -> Create ScanContext
  -> DockerManager.setup_sandbox()
  -> OrchestratorAgent.run_scan()
  -> ReportBuilder.build()
  -> Render JSON/HTML/PDF/SARIF/CSV/Markdown
  -> DockerManager.cleanup()
```

Key modules:

- `src/aisec/cli/scan.py`: scan CLI.
- `src/aisec/docker_/`: sandbox and instrumentation.
- `src/aisec/agents/`: specialized analysis agents.
- `src/aisec/reports/`: report builder and renderers.

## Components

### CLI Layer (`src/aisec/cli/`)

- `evaluate`: model/orchestrator evaluation.
- `scan`: deep security scans.
- `serve`: API and dashboard.
- `agents`: built-in agent inspection.
- `report`, `plugins`, `config`: supporting commands.

### Evaluation Layer (`src/aisec/evaluation/`)

- Stable protocol models.
- Descriptor-based findings.
- Framework mapping.
- Policy verdict generation.

### Core Layer (`src/aisec/core/`)

- Domain models.
- Configuration.
- History and audit logging.
- Metrics.
- Scheduler.
- Cloud storage.
- Correlation.

### Agent Layer (`src/aisec/agents/`)

36 specialized agents for:

- Prompt security.
- RAG security.
- MCP security.
- Tool-chain security.
- Memory security.
- Privacy and data lineage.
- API security.
- Supply chain.
- Runtime behavior.
- Falco runtime monitoring.
- Agent-on-agent review, delegation, handoff, identity, memory, and dissent
  analysis through `agentic_review`.

### API Layer (`src/aisec/api/`)

- Django REST Framework endpoints.
- OpenAPI schema.
- Auth, throttle, middleware.
- Scan runner.
- Health probes.

### Dashboard Layer (`src/aisec/dashboard/`)

- Web UI for scan and finding exploration.
- Trends, policies, findings, scan details.

### Framework Layer (`src/aisec/frameworks/`)

Framework definitions and mappings:

- OWASP LLM Top 10.
- OWASP Agentic Top 10.
- NIST AI RMF.
- NIST AI 600-1.
- EU AI Act.
- ISO/IEC 42001.
- GDPR.
- CCPA.
- Habeas Data.

## Integration Boundary

AiSec should be integrated out-of-process by default:

```text
OrchestAI adapter
  -> writes request JSON
  -> invokes AiSec CLI/container/API
  -> reads result JSON
  -> stores immutable evidence
```

This protects both repositories:

- OrchestAI does not depend on AiSec internals.
- AiSec can evolve as a reusable product.
- The JSON schema is the compatibility contract.

Supported integration modes:

- CLI: `aisec evaluate model --input request.json --output result.json`.
- Container: run the same CLI in an AiSec image.
- API: run `aisec serve` and call API endpoints when service mode is preferred.
- CI: copy the GitHub Actions or GitLab CI examples from `docs/examples/`.

## Data Contracts

### Input

`ModelRiskEvaluationRequest`

Includes:

- `schema_version`
- `request_id`
- `source`
- `target`
- `frameworks`
- `context`
- `policy`

### Output

`ModelRiskEvaluationResult`

Includes:

- `evaluation_id`
- `overall_risk`
- `risk_score`
- `findings`
- `frameworks`
- `evidence`
- `recommendations`
- `policy_verdict`

## Design Principles

- Contract-first integration.
- Optional adapters.
- Explicit evidence.
- No hidden platform coupling.
- Framework mappings are first-class.
- Descriptor evaluation should be fast.
- Deep scans should be available when extra assurance is required.
