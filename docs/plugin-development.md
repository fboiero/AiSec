# Plugin Development Guide

## Overview

AiSec uses Python's `entry_points` mechanism for plugin discovery, the same pattern used by pytest, tox, and other mature tools. Plugins can register custom security analysis agents that integrate seamlessly with the scan pipeline, report generation, and compliance mapping.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  AiSec CLI / API                                 │
│  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ AgentRegistry │←─│ discover_plugins()        │  │
│  │  .register()  │  │ (entry_points discovery)  │  │
│  └──────┬───────┘  └──────────────────────────┘  │
│         │                                         │
│  ┌──────▼───────┐  ┌──────────────────────────┐  │
│  │  Orchestrator │─→│ BaseAgent.run()           │  │
│  │  (DAG-based)  │  │  setup → analyze → teardown│ │
│  └──────────────┘  └──────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

Plugins are loaded at scan time via `importlib.metadata.entry_points()`. Each plugin implements the `AiSecPlugin` protocol and registers one or more `BaseAgent` subclasses.

## Plugin Interface

Your plugin class must satisfy the `AiSecPlugin` protocol:

```python
from aisec.plugins.interface import AiSecPlugin

class AiSecPlugin(Protocol):
    name: str           # Unique plugin identifier (e.g. "my-plugin")
    version: str        # SemVer version string
    description: str    # Short description

    def register_agents(self, registry: AgentRegistry) -> None:
        """Register custom agents with the agent registry."""
        ...
```

This is a `runtime_checkable` Protocol — your class does not need to inherit from it, just implement the required attributes and methods.

## Creating a Plugin

### Step 1: Project Structure

```
my-aisec-plugin/
├── pyproject.toml
├── src/
│   └── my_aisec_plugin/
│       ├── __init__.py     # Plugin class
│       └── agents/
│           ├── __init__.py
│           └── custom_agent.py
└── tests/
    └── test_custom_agent.py
```

### Step 2: Implement the Agent

Agents must subclass `BaseAgent` and implement the `analyze()` method:

```python
# src/my_aisec_plugin/agents/custom_agent.py
from __future__ import annotations

from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence


class MyCustomAgent(BaseAgent):
    """Custom security check for internal API key rotation."""

    name: ClassVar[str] = "api_key_rotation"
    description: ClassVar[str] = "Checks API key rotation policies and stale keys"
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["owasp_llm", "nist_ai_rmf"]
    depends_on: ClassVar[list[str]] = []  # Run independently

    async def setup(self) -> None:
        """Optional: prepare resources before analysis."""
        self._api_key_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9]{20,}",
            r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
        ]

    async def analyze(self) -> None:
        """Core analysis logic. Must populate self.findings via add_finding()."""
        # Access the scan context
        ctx = self.context

        # Access Docker filesystem if available
        if ctx.docker_manager and ctx.container_id:
            result = ctx.docker_manager.exec_in_container(
                ctx.container_id,
                ["find", "/app", "-name", "*.py", "-size", "+0c"],
            )
            files = result.stdout.strip().split("\n") if result.stdout else []

            for filepath in files:
                content_result = ctx.docker_manager.exec_in_container(
                    ctx.container_id, ["cat", filepath]
                )
                content = content_result.stdout or ""
                self._scan_file(filepath, content)

        # Access results from other agents (if depends_on is set)
        # network_result = ctx.agent_results.get("network")

    def _scan_file(self, filepath: str, content: str) -> None:
        import re

        for pattern in self._api_key_patterns:
            matches = re.findall(pattern, content)
            if matches:
                self.add_finding(
                    title="Hardcoded API Key Detected",
                    description=(
                        f"Found {len(matches)} potential API key(s) in {filepath}. "
                        "Hardcoded keys should be replaced with environment variables "
                        "or a secrets manager."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM02"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["GOVERN-1.1"],
                    evidence=[
                        Evidence(
                            source=filepath,
                            data=f"Pattern match: {pattern} ({len(matches)} hits)",
                        )
                    ],
                    remediation=(
                        "Move API keys to environment variables or a secrets vault. "
                        "Implement key rotation with a maximum lifetime of 90 days."
                    ),
                    references=[
                        "https://owasp.org/API-Security/",
                    ],
                )

    async def teardown(self) -> None:
        """Optional: clean up resources."""
        self._api_key_patterns = []
```

### Step 3: Implement the Plugin Class

```python
# src/my_aisec_plugin/__init__.py
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aisec.agents.registry import AgentRegistry


class MyPlugin:
    """AiSec plugin for API key security analysis."""

    name = "api-key-checker"
    version = "1.0.0"
    description = "Detects hardcoded API keys and rotation policy issues"

    def register_agents(self, registry: AgentRegistry) -> None:
        from my_aisec_plugin.agents.custom_agent import MyCustomAgent

        registry.register(MyCustomAgent)
```

### Step 4: Register the Entry Point

In your plugin's `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-aisec-plugin"
version = "1.0.0"
dependencies = ["aisec>=1.0.0"]

[project.entry-points."aisec.plugins"]
api-key-checker = "my_aisec_plugin:MyPlugin"
```

### Step 5: Install and Verify

```bash
# Install in development mode
pip install -e ./my-aisec-plugin

# Verify the plugin is discovered
aisec plugins list

# Run a scan — your agent runs automatically
aisec scan run myapp:latest
```

## BaseAgent Reference

### Class Variables

| Attribute     | Type              | Description                                    |
|---------------|-------------------|------------------------------------------------|
| `name`        | `str`             | Unique agent identifier (used in CLI/config)   |
| `description` | `str`             | Human-readable description                     |
| `phase`       | `AgentPhase`      | `STATIC`, `DYNAMIC`, or `POST`                 |
| `frameworks`  | `list[str]`       | Compliance frameworks this agent covers        |
| `depends_on`  | `list[str]`       | Agent names that must run before this one       |

### Agent Phases

- **`STATIC`** — Runs without Docker container access. Analyzes configuration, dependencies, and static files.
- **`DYNAMIC`** — Runs with a live Docker container. Can exec commands, monitor network, inspect filesystems.
- **`POST`** — Runs after all other agents. Can access results from previous agents via `context.agent_results`.

### Lifecycle Methods

```python
async def setup(self) -> None:
    """Called before analyze(). Initialize resources, connections, patterns."""

async def analyze(self) -> None:
    """Core analysis. MUST be implemented. Populate findings via add_finding()."""

async def teardown(self) -> None:
    """Called after analyze() (even if it raises). Clean up resources."""
```

### The `add_finding()` Method

```python
def add_finding(
    self,
    title: str,                              # Short finding title
    description: str,                        # Detailed description
    severity: Severity,                      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    *,
    owasp_llm: list[str] | None = None,     # e.g. ["LLM01", "LLM02"]
    owasp_agentic: list[str] | None = None,  # e.g. ["ASI01", "ASI06"]
    nist_ai_rmf: list[str] | None = None,    # e.g. ["GOVERN-1.1"]
    evidence: list[Evidence] | None = None,  # Supporting evidence
    remediation: str = "",                   # Fix recommendation
    references: list[str] | None = None,     # URLs
    cvss_score: float | None = None,         # CVSS 3.1 base score (0-10)
    ai_risk_score: float | None = None,      # AI-CVSS score (0-100)
) -> Finding:
```

Each call to `add_finding()` also emits a `"finding.new"` event on the context event bus.

### Severity Levels

| Level      | Use When                                                |
|------------|--------------------------------------------------------|
| `CRITICAL` | Immediate exploitation risk, active vulnerability       |
| `HIGH`     | Serious security issue requiring prompt remediation     |
| `MEDIUM`   | Moderate risk, should be addressed in next sprint       |
| `LOW`      | Minor issue, best-practice recommendation               |
| `INFO`     | Informational observation, no direct risk               |

## ScanContext Reference

The `self.context` object provides shared state across agents:

```python
context.scan_id          # UUID — unique scan identifier
context.target_image     # str — Docker image being scanned
context.target_name      # str — friendly target name
context.container_id     # str | None — Docker container ID (DYNAMIC phase)
context.config           # AiSecConfig — scan configuration
context.agent_results    # dict[str, AgentResult] — completed agent results
context.event_bus        # EventBus — publish/subscribe events
context.docker_manager   # DockerManager | None — Docker operations
context.started_at       # datetime — scan start time (UTC)
context.metadata         # dict — arbitrary metadata
```

## Event System

The `EventBus` supports publish/subscribe for inter-agent communication:

```python
# Subscribe to events (in setup)
async def setup(self) -> None:
    self.context.event_bus.on("finding.new", self._on_new_finding)

def _on_new_finding(self, finding: Finding) -> None:
    """React to findings from other agents."""
    if finding.severity == Severity.CRITICAL:
        self._critical_count += 1

# Built-in events:
#   "finding.new"       — emitted by add_finding() with the Finding object
#   "agent.started"     — emitted by orchestrator with agent name
#   "agent.completed"   — emitted by orchestrator with AgentResult
#   "scan.started"      — emitted at scan begin
#   "scan.completed"    — emitted at scan end with full results
```

## Compliance Framework Mapping

Map your findings to compliance frameworks using the `owasp_llm`, `owasp_agentic`, and `nist_ai_rmf` parameters:

### OWASP LLM Top 10 (2025)

| ID    | Category                            |
|-------|-------------------------------------|
| LLM01 | Prompt Injection                    |
| LLM02 | Sensitive Information Disclosure    |
| LLM03 | Supply Chain                        |
| LLM04 | Data and Model Poisoning            |
| LLM05 | Improper Output Handling            |
| LLM06 | Excessive Agency                    |
| LLM07 | System Prompt Leakage               |
| LLM08 | Vector and Embedding Weaknesses     |
| LLM09 | Misinformation                      |
| LLM10 | Unbounded Consumption               |

### OWASP Agentic Security Initiatives Top 10 (2026)

| ID    | Category                            |
|-------|-------------------------------------|
| ASI01 | Agent Goal Hijacking                |
| ASI02 | Tool Misuse                         |
| ASI03 | Identity and Privilege Abuse        |
| ASI04 | Supply Chain Vulnerabilities        |
| ASI05 | Unexpected Code Execution           |
| ASI06 | Memory and Context Poisoning        |
| ASI07 | Insecure Inter-Agent Communication  |
| ASI08 | Cascading Failures                  |
| ASI09 | Human-Agent Trust Exploitation      |
| ASI10 | Rogue Agents                        |

## Testing Your Plugin

```python
# tests/test_custom_agent.py
import pytest
from unittest.mock import MagicMock

from aisec.core.context import ScanContext
from aisec.core.events import EventBus

from my_aisec_plugin.agents.custom_agent import MyCustomAgent


@pytest.fixture
def scan_context():
    ctx = ScanContext(
        target_image="test:latest",
        target_name="test",
    )
    return ctx


class TestMyCustomAgent:
    @pytest.mark.asyncio
    async def test_agent_has_metadata(self, scan_context):
        agent = MyCustomAgent(scan_context)
        assert agent.name == "api_key_rotation"
        assert agent.description != ""

    @pytest.mark.asyncio
    async def test_no_findings_on_clean_code(self, scan_context):
        agent = MyCustomAgent(scan_context)
        result = await agent.run()
        # No container = no files to scan = no findings
        assert len(result.findings) == 0
        assert result.error is None

    @pytest.mark.asyncio
    async def test_detects_hardcoded_key(self, scan_context):
        agent = MyCustomAgent(scan_context)
        await agent.setup()
        # Directly call internal method with test data
        agent._scan_file(
            "/app/config.py",
            'API_KEY = "EXAMPLE_KEY_DO_NOT_USE_1234567890abcdef"',
        )
        assert len(agent.findings) == 1
        assert agent.findings[0].severity.value == "high"

    @pytest.mark.asyncio
    async def test_finding_has_compliance_mapping(self, scan_context):
        agent = MyCustomAgent(scan_context)
        await agent.setup()
        agent._scan_file(
            "/app/config.py",
            'api_key = "EXAMPLEKEY1234567890X"',
        )
        assert len(agent.findings) >= 1
        finding = agent.findings[0]
        assert "LLM02" in finding.owasp_llm
        assert finding.remediation != ""
```

Run tests:

```bash
# From your plugin directory
pytest tests/ -v

# With coverage
pytest tests/ --cov=my_aisec_plugin --cov-report=term-missing
```

## Advanced Patterns

### Agent Dependencies

Use `depends_on` to ensure your agent runs after others:

```python
class PostAnalysisAgent(BaseAgent):
    name: ClassVar[str] = "post_analysis"
    phase: ClassVar[AgentPhase] = AgentPhase.POST
    depends_on: ClassVar[list[str]] = ["network", "dataflow", "privacy"]

    async def analyze(self) -> None:
        # Access results from dependency agents
        network = self.context.agent_results.get("network")
        dataflow = self.context.agent_results.get("dataflow")

        if network and dataflow:
            # Cross-reference network findings with data flow
            net_findings = network.findings
            data_findings = dataflow.findings
            # ... correlate findings ...
```

### Multiple Agents Per Plugin

```python
class MyPlugin:
    name = "security-suite"
    version = "2.0.0"
    description = "Comprehensive security analysis suite"

    def register_agents(self, registry: AgentRegistry) -> None:
        from my_plugin.agents import (
            ApiKeyAgent,
            AuthFlowAgent,
            SessionAgent,
        )
        registry.register(ApiKeyAgent)
        registry.register(AuthFlowAgent)
        registry.register(SessionAgent)
```

### Custom Evidence

```python
from aisec.core.models import Evidence

# Text evidence
Evidence(source="/app/config.py", data="API_KEY = 'EXAMPLE_KEY_...'")

# Structured evidence
Evidence(
    source="network_capture",
    data="Unencrypted HTTP POST to api.example.com:80 with Authorization header",
)

# Command output evidence
Evidence(
    source="docker exec: nmap scan",
    data="22/tcp open ssh\n80/tcp open http\n443/tcp open https",
)
```

## Debugging

Enable debug logging to troubleshoot plugin loading:

```bash
# See plugin discovery logs
AISEC_LOG_LEVEL=DEBUG aisec plugins list

# See agent execution logs
AISEC_LOG_LEVEL=DEBUG aisec scan run myapp:latest
```

Common issues:

1. **Plugin not discovered** — Verify the entry point name in `pyproject.toml` matches the group `aisec.plugins`. Reinstall the package.
2. **Agent not running** — Check `agent.name` is unique and not in `skip_agents` config.
3. **Import errors** — Use lazy imports inside `register_agents()` to avoid circular dependencies.
4. **No findings generated** — Verify `add_finding()` is called (not just `Finding()` constructor). Check the phase matches your analysis needs (DYNAMIC for Docker access).
