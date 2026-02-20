# Security Analysis Agents

## Agent Lifecycle

Every agent follows the same lifecycle defined by `BaseAgent`:

1. **setup()** - Allocate resources, connect to services
2. **analyze()** - Core analysis logic (must populate `self.findings`)
3. **teardown()** - Clean up resources

## Built-in Agents

### NetworkAgent
Analyzes network exposure, open ports, WebSocket security, TLS configuration, and outbound connections.

### DataFlowAgent
Traces data flow through the agent. Detects PII (emails, phones, SSNs, credit cards, Argentine DNI), plaintext credentials, and unencrypted data storage.

### PrivacyAgent
Evaluates compliance with GDPR, CCPA, and Argentina's Habeas Data (Ley 25.326). Generates compliance checklists.

### PromptSecurityAgent
Tests for prompt injection vulnerabilities (direct, indirect, tool hijacking), system prompt leakage, and validates input sanitization.

### SupplyChainAgent
Analyzes Docker image layers, dependency files, known CVEs (via Trivy), embedded secrets, and unpinned dependencies.

### PermissionAgent
Checks for excessive agency: root containers, unrestricted shell access, Docker capabilities, and human-in-the-loop controls.

### OutputAgent
Validates output sanitization, checks for PII/credential leakage in outputs, and verifies error message information disclosure.

## Creating Custom Agents

```python
from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity

class MyAgent(BaseAgent):
    name = "my_agent"
    description = "My custom security check"
    phase = AgentPhase.DYNAMIC
    depends_on = []  # or ["network"] if you need network results

    async def analyze(self):
        # Your analysis logic
        self.add_finding(
            title="Issue Found",
            description="Details...",
            severity=Severity.HIGH,
            owasp_llm=["LLM06"],
            remediation="How to fix...",
        )
```
