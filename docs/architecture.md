# AiSec Architecture

## Overview

AiSec uses a multi-agent architecture where specialized security analysis agents work in parallel inside isolated Docker environments.

## Components

### CLI Layer (`src/aisec/cli/`)
- Entry point for all user interactions
- Built with Typer + Rich for a modern terminal experience
- Commands: `scan`, `report`, `plugins`, `config`

### Core Layer (`src/aisec/core/`)
- Domain models: `Finding`, `Evidence`, `ScanContext`, `AgentResult`
- Configuration: Pydantic Settings with YAML/env/CLI layering
- Event bus for inter-agent communication

### Agent Layer (`src/aisec/agents/`)
- `BaseAgent` ABC defining the lifecycle: `setup()` -> `analyze()` -> `teardown()`
- 7 specialized agents (network, dataflow, privacy, prompt_security, supply_chain, permission, output)
- `OrchestratorAgent` with DAG-based scheduling for concurrent execution

### Docker Layer (`src/aisec/docker_/`)
- `DockerManager` for container lifecycle management
- Sandbox isolation with dedicated bridge networks
- Network capture and filesystem monitoring sidecars

### Framework Layer (`src/aisec/frameworks/`)
- OWASP LLM Top 10 (2025) definitions and mapping
- OWASP Agentic Top 10 (2026) definitions and mapping
- NIST AI RMF function mapping
- Compliance evaluators: GDPR, CCPA, Habeas Data (Ley 25.326)

### Reports Layer (`src/aisec/reports/`)
- AI-CVSS scoring engine
- Report builder assembling findings from all agents
- Renderers: JSON, HTML (Jinja2), PDF (WeasyPrint)
- i18n support for English and Spanish

### Plugin Layer (`src/aisec/plugins/`)
- Entry-point-based plugin discovery
- `AiSecPlugin` protocol for custom agents and checks

## Execution Flow

```
CLI (aisec scan)
  -> Load Config
  -> Create ScanContext
  -> DockerManager.setup_sandbox()
  -> OrchestratorAgent.run_scan()
    -> Phase 1 (STATIC): SupplyChainAgent
    -> Phase 2 (DYNAMIC): NetworkAgent | DataFlowAgent | PermissionAgent
    -> Phase 3 (DYNAMIC): PromptSecurityAgent | OutputAgent
    -> Phase 4 (POST): PrivacyAgent
  -> ReportBuilder.build()
  -> Render (JSON/HTML/PDF)
  -> DockerManager.cleanup()
```
