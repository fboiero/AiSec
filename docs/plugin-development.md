# Plugin Development Guide

## Overview

AiSec uses Python's `entry_points` mechanism for plugin discovery, the same pattern used by pytest and other mature tools.

## Creating a Plugin

### 1. Implement the Plugin Class

```python
# my_aisec_plugin/__init__.py
from aisec.agents.base import BaseAgent
from aisec.agents.registry import AgentRegistry
from aisec.core.enums import AgentPhase, Severity
from aisec.plugins.interface import AiSecPlugin


class MyCustomAgent(BaseAgent):
    name = "my_custom_check"
    description = "Custom security check for XYZ"
    phase = AgentPhase.DYNAMIC

    async def analyze(self):
        # Your analysis logic here
        self.add_finding(
            title="Custom Issue",
            description="Found a custom issue",
            severity=Severity.MEDIUM,
        )


class MyPlugin:
    name = "my-plugin"
    version = "1.0.0"
    description = "My custom AiSec plugin"

    def register_agents(self, registry: AgentRegistry) -> None:
        registry.register(MyCustomAgent)
```

### 2. Register the Entry Point

In your plugin's `pyproject.toml`:

```toml
[project.entry-points."aisec.plugins"]
my-plugin = "my_aisec_plugin:MyPlugin"
```

### 3. Install and Verify

```bash
pip install my-aisec-plugin
aisec plugins list
```

Your plugin's agents will automatically be discovered and included in scans.
