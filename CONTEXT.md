# AiSec Session Context

## Current Goal
v1.5.0 is **fully implemented and tested**. Pending: README update, git commit, tag, push, GitHub release.

## Plan
v1.5.0 — Agentic Runtime Security, RAG/MCP Hardening & Auto-Remediation (delivered and tested).

## Completed
- **6 new agents** created and registered (34 total):
  - `rag_security` — RAG pipeline security (loaders, retrieval, context stuffing, injection, grounding)
  - `mcp_security` — MCP server security (auth, schemas, transport, approval, path traversal)
  - `tool_chain` — Tool chain security (sandbox, file/network/DB restrictions, output injection)
  - `agent_memory` — Agent memory security (encryption, access control, poisoning, growth, serialization)
  - `fine_tuning` — Fine-tuning pipeline security (data validation, PII, provenance, secrets, registry)
  - `cicd_pipeline` — CI/CD pipeline security (secrets, model signing, pip safety, Docker privilege)
- **Auto-Remediation Engine** (`src/aisec/remediation/`) with 16+ strategies, code patches, effort estimation
- **Policy-as-Code Engine** (`src/aisec/policies/`) with 3 built-in policies (strict/moderate/permissive)
- **8 new correlation rules** added (26 total) in `core/correlation.py`
- **Registry** updated with 6 new agent imports (34 total)
- **Version** bumped to 1.5.0 in `pyproject.toml` and `__init__.py`
- **CHANGELOG.md** updated with v1.5.0 entry
- **8 test files** created (154 new tests, 1098 total pass, 2 skipped)

## Pending
- **README.md** update (34 agents, new table rows, architecture diagram, roadmap)
- **Git commit** with detailed message
- **Git tag** v1.5.0
- **Git push** to origin/main (may need `/tmp` clone workaround for SIGBUS)
- **GitHub Release** with changelog

## Key Decisions
- RAG security as dedicated agent (not extension of embedding_leakage) — distinct attack surface
- MCP security focused on server-side (tool schemas, auth, transport) — highest impact area
- Tool chain agent covers function calling broadly (not just MCP) — LangChain, CrewAI, custom tools
- Policy engine uses YAML not OPA/Rego — simpler, no new dependencies, fits AiSec patterns
- Remediation engine generates static fix suggestions (no LLM-powered analysis) — deterministic, fast
- 3 built-in policies map to deployment stages: strict=prod, moderate=staging, permissive=dev

## Relevant Paths
- New agents: `src/aisec/agents/{rag_security,mcp_security,tool_chain,agent_memory,fine_tuning,cicd_pipeline}.py`
- Remediation: `src/aisec/remediation/{engine,strategies,models}.py`
- Policies: `src/aisec/policies/{engine,models,loader}.py`, `builtin/{strict,moderate,permissive}.yaml`
- Correlation: `src/aisec/core/correlation.py`
- Registry: `src/aisec/agents/registry.py`
- Tests: `tests/unit/agents/test_{rag_security,mcp_security,tool_chain,agent_memory,fine_tuning,cicd_pipeline}_agent.py`, `tests/unit/test_{remediation,policy}_engine.py`

## Commands
- Run tests: `PYTHONPATH=src python3 -m pytest tests/ -x -q`
- Verify agents: `PYTHONPATH=src python3 -c "from aisec.agents.registry import default_registry, register_core_agents; register_core_agents(); print(len(default_registry.get_all()))"`
