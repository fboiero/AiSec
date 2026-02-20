<p align="center">
  <img src="docs/assets/aisec-logo.png" alt="AiSec Logo" width="200" />
</p>

<h1 align="center">AiSec</h1>

<p align="center">
  <strong>Deep security analysis framework for autonomous AI agent implementations</strong>
</p>

<p align="center">
  <a href="https://github.com/fboiero/AiSec/actions/workflows/ci.yml"><img src="https://github.com/fboiero/AiSec/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/aisec/"><img src="https://img.shields.io/pypi/v/aisec.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/aisec/"><img src="https://img.shields.io/pypi/pyversions/aisec.svg" alt="Python"></a>
  <a href="https://github.com/fboiero/AiSec/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/fboiero/AiSec/issues"><img src="https://img.shields.io/github/issues/fboiero/AiSec.svg" alt="Issues"></a>
</p>

---

## What is AiSec?

AiSec is an open-source, multi-agent security analysis framework designed to perform deep security audits of autonomous AI agent implementations like [OpenClaw](https://openclaw.ai/), custom LLM agents, and other agentic AI systems.

Unlike traditional container scanners (Trivy, Clair) that focus on CVEs in OS packages, **AiSec analyzes AI-specific attack vectors**: prompt injection, excessive agency, data exfiltration, privacy compliance, and more.

### Key Features

- **Multi-Agent Analysis** - Specialized security agents work in parallel, each focused on a specific attack domain
- **Docker-Based Sandboxing** - Spins up target AI agents in isolated Docker environments with full network and filesystem instrumentation
- **Framework Compliance** - Maps findings to OWASP LLM Top 10 (2025), OWASP Agentic Top 10 (2026), and NIST AI RMF
- **Privacy Regulation Checks** - Compliance assessment for GDPR, CCPA, and Argentina's Habeas Data (Ley 25.326)
- **AI-CVSS Scoring** - Extended CVSS scoring with AI-specific risk dimensions (autonomy impact, cascade potential, persistence risk)
- **Rich Reporting** - Detailed reports in JSON, HTML, and PDF with executive summaries and remediation guidance
- **Plugin System** - Extensible architecture for custom analysis agents and compliance frameworks
- **Multilingual** - Reports available in English and Spanish

## Architecture

```
                         +------------------+
                         |   AiSec CLI      |
                         |   (aisec scan)   |
                         +--------+---------+
                                  |
                         +--------v---------+
                         |   Orchestrator   |
                         |   Agent (DAG)    |
                         +--------+---------+
                                  |
              +-------------------+-------------------+
              |         |         |         |         |
        +-----v---+ +---v-----+ +v-------+ +v------+ +v---------+
        | Network  | |DataFlow | |Privacy | |Prompt | |Supply    |
        | Agent    | |Agent    | |Agent   | |Sec.   | |Chain     |
        +----------+ +---------+ +--------+ |Agent  | |Agent     |
                                             +-------+ +----------+
              +-------------------+-------------------+
              |                                       |
        +-----v-------+                       +-------v------+
        | Permission  |                       |   Output     |
        | Agent       |                       |   Agent      |
        +-------------+                       +--------------+
              |
    +---------v-----------+
    |   Docker Sandbox    |
    |  +---------------+  |
    |  | Target Agent  |  |
    |  | (e.g. OpenClaw)|  |
    |  +---------------+  |
    |  | tcpdump sidecar|  |
    |  | fs-monitor     |  |
    |  +---------------+  |
    +---------------------+
              |
    +---------v-----------+
    |   Report Builder    |
    |  JSON | HTML | PDF  |
    +---------------------+
```

## Security Analysis Agents

| Agent | Focus Area | OWASP Mapping |
|-------|-----------|---------------|
| **NetworkAgent** | Open ports, WebSocket security, TLS config, DNS exfiltration | LLM09, ASI07, ASI08 |
| **DataFlowAgent** | PII detection, encryption at rest/transit, data retention | LLM02, ASI06 |
| **PrivacyAgent** | GDPR, CCPA, Habeas Data compliance assessment | LLM02 |
| **PromptSecurityAgent** | Direct/indirect prompt injection, tool hijacking, jailbreaks | LLM01, LLM07, ASI01 |
| **SupplyChainAgent** | Docker layer CVEs, dependency vulnerabilities, SBOM | LLM03, ASI04, ASI05 |
| **PermissionAgent** | Excessive agency, privilege escalation, tool access scope | LLM06, ASI02, ASI03 |
| **OutputAgent** | Output sanitization, information leakage, XSS vectors | LLM05, ASI09 |

## Quick Start

### Prerequisites

- Python 3.11+
- Docker Engine running
- (Optional) [Trivy](https://trivy.dev/) for enhanced CVE scanning

### Installation

```bash
# Install from PyPI
pip install aisec

# Install with all optional dependencies
pip install aisec[all]

# Or install from source
git clone https://github.com/fboiero/AiSec.git
cd AiSec
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Run a full security scan against an AI agent Docker image
aisec scan ghcr.io/openclaw/openclaw:latest

# Scan with specific agents only
aisec scan myagent:latest --agents network,prompt_security,permission

# Generate reports in multiple formats
aisec scan myagent:latest --format json,html,pdf

# Generate report in Spanish
aisec scan myagent:latest --lang es

# Run with specific compliance frameworks
aisec scan myagent:latest --compliance gdpr,habeas_data

# Use a configuration file
aisec scan myagent:latest --config aisec.yaml
```

### Configuration

Generate a default configuration file:

```bash
aisec config init
```

This creates `aisec.yaml`:

```yaml
target:
  image: ""
  name: ""
  type: "generic"  # openclaw, generic, custom

scan:
  timeout: 3600
  agents:
    - network
    - dataflow
    - privacy
    - prompt_security
    - supply_chain
    - permission
    - output

report:
  format: ["json", "html"]
  language: "en"
  output_dir: "./aisec-reports"

compliance:
  frameworks: ["gdpr", "ccpa", "habeas_data"]
```

## Compliance Frameworks

### OWASP LLM Top 10 (2025)
Full coverage of all 10 categories from prompt injection (LLM01) through unbounded consumption (LLM10).

### OWASP Top 10 for Agentic Applications (2026)
Assessment against agent-specific risks: goal hijacking, tool misuse, identity abuse, supply chain, code execution, memory poisoning, inter-agent communication, cascading failures, trust exploitation, and rogue agents.

### NIST AI Risk Management Framework
Mapping to GOVERN, MAP, MEASURE, and MANAGE functions with subcategory-level assessment.

### Privacy Regulations
- **GDPR** (EU) - Articles 5-9, 12-22, 25, 32-35
- **CCPA** (California) - Right to know, delete, opt-out
- **Habeas Data** (Argentina, Ley 25.326) - Articles 2-8, 11-12, 14, 16, 26-27

## Report Example

AiSec generates comprehensive security reports with:

- **Executive Summary** - Overall risk level, key statistics, top risks
- **Risk Dashboard** - Composite AI risk score (0-100) across 5 dimensions
- **Framework Assessment** - Finding-by-finding OWASP and NIST mapping
- **Compliance Checklists** - Pass/fail per regulation article
- **Detailed Findings** - Evidence, AI-CVSS score, remediation steps
- **Appendices** - Methodology, raw data references, glossary

## Plugin Development

Create custom analysis agents:

```python
# my_plugin.py
from aisec.agents.base import BaseAgent
from aisec.plugins.interface import AiSecPlugin

class MyCustomAgent(BaseAgent):
    name = "my_custom_check"
    description = "Custom security check"

    async def analyze(self):
        # Your analysis logic here
        self.add_finding(...)

class MyPlugin(AiSecPlugin):
    name = "my-plugin"
    version = "1.0.0"

    def register_agents(self, registry):
        registry.register(MyCustomAgent)
```

Register in `pyproject.toml`:

```toml
[project.entry-points."aisec.plugins"]
my-plugin = "my_plugin:MyPlugin"
```

## Development

```bash
# Clone the repository
git clone https://github.com/fboiero/AiSec.git
cd AiSec

# Install in development mode
pip install -e ".[dev,all]"

# Run tests
pytest

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/aisec/
```

## Roadmap

- [x] Core agent framework and orchestrator
- [x] Docker sandbox with network/filesystem instrumentation
- [x] 7 specialized security analysis agents
- [x] OWASP LLM Top 10 + Agentic Top 10 mapping
- [x] NIST AI RMF assessment
- [x] GDPR, CCPA, Habeas Data compliance
- [x] AI-CVSS risk scoring
- [x] JSON, HTML, PDF report generation
- [ ] Interactive TUI dashboard (Rich Live)
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] OpenClaw-specific deep analysis plugin
- [ ] Multi-agent system cascade analysis
- [ ] API mode for programmatic access
- [ ] Cloud deployment (AWS, GCP, Azure)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

AiSec is licensed under the [Apache License 2.0](LICENSE).

## Acknowledgments

- [OWASP GenAI Security Project](https://genai.owasp.org/) for the LLM and Agentic Top 10 frameworks
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) for AI governance standards
- [Trivy](https://trivy.dev/) for container vulnerability scanning inspiration
- The open-source AI security research community

---

<p align="center">
  Made with security in mind by <a href="https://github.com/fboiero">Federico Boiero</a>
</p>
