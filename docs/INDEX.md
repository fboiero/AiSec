# AiSec Documentation Index

## Start Here

- [README](../README.md): product overview and primary use cases.
- [Agent Handoff](AGENT_HANDOFF.md): current state and integration notes for another coding agent.
- [Quick Start](quickstart.md): install and run `evaluate` or `scan`.
- [Architecture](architecture.md): evaluation path, scan path, and integration boundary.
- [Managed Deployment](managed-deployment.md): Compose, Kubernetes, and Helm service path.
- [Managed Pilot Report Template](managed-pilot-report-template.md): go/no-go report for external pilots.
- [Product Strategy 2026](product-strategy-2026.md): positioning and execution plan.
- [Project Plan 2026](../PROJECT_PLAN_2026.md): roadmap and acceptance criteria.

## Orchestrator Integration

- [Orchestrator Integration Protocol](orchestai-integration-protocol.md): JSON contract and adapter guidance.
- [Orchestrator Adapter Guide](orchestrator-adapter-guide.md): reusable adapter pattern for other platforms.
- [Model-risk request schema](schemas/model-risk-request.schema.json): JSON Schema for requests.
- [Model-risk result schema](schemas/model-risk-result.schema.json): JSON Schema for results.
- API evaluation history: `GET /api/evaluations/` and `GET /api/evaluations/{evaluation_id}/`.
- API evaluation rollup: `GET /api/evaluations/rollup/`.
- API approved baselines: `GET/POST /api/evaluation-baselines/`.
- API accepted exceptions: `GET/POST /api/evaluation-exceptions/`.

## Examples And Adapters

- [Python subprocess adapter](examples/aisec_subprocess_adapter.py)
- [HTTP adapter for `aisec serve`](examples/aisec_http_adapter.py)
- [GitHub Actions model-risk gate](examples/github-actions-model-risk.yml)
- [GitLab CI model-risk gate](examples/gitlab-model-risk.yml)
- `aisec evaluate summarize`: generate Markdown/JSON summaries from model-risk result artifacts.
- `aisec evaluate evidence`: export model-risk evidence grouped by governance framework.
- `aisec evaluate compare`: compare current model-risk evidence against an approved baseline.
- [OrchestAI RAG request](examples/orchestai-model-risk-request.json)
- [OrchestAI RAG result](examples/orchestai-model-risk-result.json)
- [OrchestAI customer-support RAG use case](examples/orchestai-usecase-customer-support-rag.json)
- [OrchestAI ops agent MCP use case](examples/orchestai-usecase-ops-agent-mcp.json)
- [Generic model route request](examples/model-route-risk-request.json)
- [Tool-enabled agent request](examples/tool-agent-risk-request.json)
- [MCP workflow request](examples/mcp-workflow-risk-request.json)

## Security And Compliance

- [Frameworks](frameworks.md): OWASP, NIST, ISO, GDPR, Habeas Data mappings.
- [Agents](agents.md): built-in security agents.
- [Plugin Development](plugin-development.md): extending AiSec.

## Historical And Research Docs

- [OpenClaw case study](case-study-openclaw-xcapit.md)
- [OpenClaw security analysis blog](blog-openclaw-security-analysis.md)
