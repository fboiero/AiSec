<p align="center">
  <img src="docs/assets/aisec-logo.png" alt="AiSec Logo" width="200" />
</p>

<h1 align="center">AiSec</h1>

<p align="center">
  <strong>AI risk and compliance evaluation engine for model orchestrators, agents, and RAG systems</strong>
</p>

<p align="center">
  <a href="https://github.com/fboiero/AiSec/actions/workflows/ci.yml"><img src="https://github.com/fboiero/AiSec/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/aisec/"><img src="https://img.shields.io/pypi/v/aisec.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/aisec/"><img src="https://img.shields.io/pypi/pyversions/aisec.svg" alt="Python"></a>
  <a href="https://github.com/fboiero/AiSec/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

---

## What Is AiSec?

AiSec is an open-source engine for evaluating security, privacy, governance, and
compliance risk in AI systems.

It can be used in two complementary ways:

1. **Model-risk evaluator for orchestrators**: platforms such as OrchestAI can
   call AiSec as an optional external evaluator for models, providers, agents,
   RAG pipelines, and workflows.
2. **Deep agent scanner**: DevSecOps teams can run AiSec against Dockerized AI
   agents to inspect prompt-injection exposure, tool misuse, RAG weaknesses,
   runtime behavior, supply chain, data flow, privacy controls, and compliance.

The main design goal is integration without lock-in. AiSec accepts explicit JSON
descriptors or Docker images, returns normalized findings and evidence, and lets
the consuming platform decide how to store, approve, block, or display the
results.

Repository:

```text
https://github.com/fboiero/AiSec
git@github.com:fboiero/AiSec.git
```

## Why It Exists

AI orchestration platforms increasingly route requests across models, providers,
tools, RAG stores, workflows, memory, and agents. Traditional scanners find CVEs
in code or containers, but they do not answer product and compliance questions
such as:

- Can this model process PII under the configured safeguards?
- Does this RAG pipeline isolate tenants and filter retrieved content?
- Can this agent call tools without approval?
- Is MCP or function calling auditable?
- Which OWASP LLM, OWASP Agentic, NIST AI RMF, ISO 42001, GDPR, and Habeas Data
  controls are affected?
- Can a compliance module store machine-readable evidence for an approval flow?

AiSec provides that missing evaluation layer.

## Primary Use Case: OrchestAI-Style Integration

OrchestAI and similar platforms can call AiSec from their compliance module:

```text
Orchestrator compliance module
  -> creates ModelRiskEvaluationRequest JSON
  -> runs aisec evaluate model --input request.json --output result.json
  -> stores ModelRiskEvaluationResult as audit/compliance evidence
```

Example:

```bash
aisec evaluate model \
  --input docs/examples/orchestai-model-risk-request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical
```

The output contains:

- `overall_risk`
- `risk_score`
- `findings`
- `frameworks`
- `evidence`
- `recommendations`
- `policy_verdict`

The integration protocol is documented in
[`docs/orchestai-integration-protocol.md`](docs/orchestai-integration-protocol.md).

## Deep Scan Use Case

AiSec also keeps its original deep security scan path for containerized agents:

```bash
aisec scan run myagent:latest --format json,html,sarif
aisec scan run myagent:latest --agents rag_security,mcp_security,tool_chain
aisec scan run myagent:latest --policy strict --gate
```

This mode uses Docker sandboxing, specialized agents, report builders, policy
gates, and optional runtime monitoring.

## Current Capabilities

- **Model-risk protocol** for orchestrators using `aisec.model_risk.v1`.
- **36 specialized security agents** for AI, agentic, code, infra, privacy, and
  runtime domains.
- **Docker sandboxing** for target agents and workloads.
- **RAG, MCP, tool-chain, agent-memory, fine-tuning, and CI/CD security agents**.
- **Agent-on-agent analysis** for reviewer independence, unsafe handoffs,
  shared credentials, shared memory, suppressed dissent, and autonomous
  high-impact actions.
- **Compliance mapping** across OWASP LLM, OWASP Agentic, NIST AI RMF,
  NIST AI 600-1, ISO/IEC 42001, EU AI Act, GDPR, CCPA, Habeas Data, and
  Argentina AI governance.
- **Policy-as-code** for advisory or blocking gates.
- **Report formats**: JSON, HTML, PDF, SARIF, CSV, Markdown.
- **REST API and dashboard** via `aisec serve`.
- **OpenAPI documentation**, audit trail, scan persistence, webhooks, scheduler,
  Prometheus metrics, structured logging, health probes.
- **Cloud deployment assets**: Docker Compose, Kubernetes manifests, Helm chart.
- **Plugin hooks** for custom agents and compliance extensions.

## Architecture

```text
                 Model Orchestrator / Compliance Module
                      OrchestAI, internal AI platform
                                  |
                                  | JSON contract
                                  v
                         aisec evaluate model
                                  |
                +-----------------+-----------------+
                |                                   |
        Descriptor risk rules              Framework mapping
        model/provider/RAG/tools           evidence + verdict
                |                                   |
                +-----------------+-----------------+
                                  |
                                  v
                    ModelRiskEvaluationResult JSON
```

Deep scan architecture:

```text
aisec scan run <docker-image>
  -> Docker sandbox
  -> DAG orchestrator
  -> 36 security agents
  -> correlated findings
  -> reports + policy verdicts
```

## Installation

```bash
pip install aisec
pip install "aisec[all]"
```

From source:

```bash
git clone https://github.com/fboiero/AiSec.git
cd AiSec
pip install -e ".[dev]"
```

## Quick Start

Evaluate an OrchestAI-style model/RAG descriptor:

```bash
aisec evaluate model \
  --input docs/examples/orchestai-model-risk-request.json \
  --output aisec-results/model-risk-result.json \
  --fail-on critical
```

Run a deep scan against an agent image:

```bash
aisec scan run ghcr.io/openclaw/openclaw:latest --format json,html,sarif
```

Start the API and dashboard:

```bash
aisec serve --port 8000
```

## Integration Contract

AiSec is intentionally used out-of-process by default:

- CLI or container for local/CI adoption.
- REST API for service-to-service integration.
- JSON request/result schemas as the compatibility boundary.

This keeps AiSec reusable across multiple products and avoids coupling a
platform like OrchestAI to AiSec internals.

Recommended adapter boundary in a consuming platform:

```text
backend/app/services/compliance/evaluators/aisec.py
```

The adapter should:

1. Build a `ModelRiskEvaluationRequest`.
2. Execute AiSec by CLI, container, or API.
3. Parse `ModelRiskEvaluationResult`.
4. Store the full result as immutable compliance evidence.
5. Show summary fields in model/provider/workflow approval screens.

## Target Users

- AI platform teams building internal model orchestration.
- Products like OrchestAI that need optional compliance evaluators.
- DevSecOps teams gating AI agents in CI/CD.
- Security teams auditing RAG, MCP, tools, memory, and autonomous workflows.
- Compliance teams collecting AI risk evidence for ISO 42001, NIST AI RMF,
  GDPR, Habeas Data, and related programs.

## Documentation

- [Agent Handoff](docs/AGENT_HANDOFF.md)
- [Quick Start](docs/quickstart.md)
- [Documentation Index](docs/INDEX.md)
- [Architecture](docs/architecture.md)
- [Frameworks](docs/frameworks.md)
- [OrchestAI Integration Protocol](docs/orchestai-integration-protocol.md)
- [Product Strategy 2026](docs/product-strategy-2026.md)
- [Project Plan 2026](PROJECT_PLAN_2026.md)
- [Plugin Development](docs/plugin-development.md)

## License

Apache License 2.0.
