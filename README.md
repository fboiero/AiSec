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

Unlike traditional container scanners (Trivy, Clair) that focus on CVEs in OS packages, **AiSec analyzes AI-specific attack vectors**: prompt injection, excessive agency, data exfiltration, privacy compliance, adversarial robustness, synthetic content risks, and multi-agent cascade failures.

### Key Features

- **15 Specialized Agents** - Security agents work in parallel, each focused on a specific attack domain
- **Docker-Based Sandboxing** - Target AI agents run in isolated Docker environments with full network and filesystem instrumentation
- **8 Compliance Frameworks** - GDPR, CCPA, Habeas Data, EU AI Act, ISO 42001, NIST AI 600-1, NIST AI RMF, Argentina AI Bill
- **100+ Risk Detectors** - Covering prompt injection, cryptographic weaknesses, supply chain, adversarial robustness, deepfakes, and more
- **AI-CVSS Scoring** - Extended CVSS scoring with AI-specific risk dimensions (autonomy impact, cascade potential, persistence risk)
- **4 Report Formats** - JSON, HTML, PDF, and SARIF for IDE/CI integration (GitHub Code Scanning, VS Code)
- **REST API** - `aisec serve` with Django REST Framework for programmatic access
- **GitHub Action** - Marketplace action with SARIF upload for automated security scanning in CI/CD
- **Scan History** - SQLite-backed trending and baseline comparison for tracking security posture over time
- **Plugin System** - Extensible architecture for custom analysis agents and compliance frameworks
- **Multilingual** - Reports available in English and Spanish

## Architecture

```
                         +------------------+
                         |    AiSec CLI     |
                         |  scan | serve    |
                         +--------+---------+
                                  |
                         +--------v---------+
                         |   Orchestrator   |
                         |   Agent (DAG)    |
                         +--------+---------+
                                  |
    +----------+----------+-------+-------+----------+----------+
    |          |          |       |       |          |          |
+---v----+ +--v-----+ +--v--+ +-v----+ +-v------+ +v-------+ +v------+
|Network | |DataFlow| |Priv.| |Prompt| |Supply  | |Permis. | |Output |
|Agent   | |Agent   | |Agent| |Sec.  | |Chain   | |Agent   | |Agent  |
+--------+ +--------+ +-----+ +------+ +--------+ +--------+ +-------+
    |          |          |       |       |          |          |
+---v----+ +--v-----+ +--v--+ +-v----+ +-v------+ +v-------+ +v------+
|Crypto  | |SBOM    | |Garak| |Guard.| |Model   | |Advers. | |Cascade|
|Agent   | |Agent   | |Agent| |Agent | |Scan    | |Agent   | |Agent  |
+--------+ +--------+ +-----+ +------+ +--------+ +--------+ +-------+
                                                                  |
                                                          +-------v--------+
                                                          |  Synthetic     |
                                                          |  Content Agent |
                                                          +----------------+
                          |
                +---------v-----------+
                |   Docker Sandbox    |
                |  +---------------+  |
                |  | Target Agent  |  |
                |  +---------------+  |
                +---------------------+
                          |
                +---------v-----------+
                |   Report Builder    |
                | JSON|HTML|PDF|SARIF |
                +---------------------+
```

## Security Analysis Agents

| Agent | Focus Area | OWASP Mapping |
|-------|-----------|---------------|
| **NetworkAgent** | Open ports, WebSocket security, TLS config, DNS exfiltration | LLM09, ASI07, ASI08 |
| **DataFlowAgent** | PII detection (Presidio), encryption at rest/transit, data retention | LLM02, ASI06 |
| **PrivacyAgent** | GDPR, CCPA, Habeas Data compliance assessment | LLM02 |
| **PromptSecurityAgent** | Direct/indirect prompt injection, tool hijacking, jailbreaks | LLM01, LLM07, ASI01 |
| **SupplyChainAgent** | Docker layer CVEs, dependency vulnerabilities, SBOM | LLM03, ASI04, ASI05 |
| **PermissionAgent** | Excessive agency, privilege escalation, tool access scope | LLM06, ASI02, ASI03 |
| **OutputAgent** | Output sanitization, information leakage, XSS vectors | LLM05, ASI09 |
| **CryptoAuditAgent** | TLS/SSL config, cipher suites, key management, quantum readiness | LLM02, LLM09 |
| **SBOMAgent** | Software Bill of Materials, license compliance, dependency depth | LLM03, ASI04 |
| **GarakAgent** | LLM vulnerability scanning (50+ probes), jailbreak, data leakage | LLM01, LLM04, LLM09 |
| **GuardrailAgent** | Safety guardrail presence (NeMo, Guardrails AI, LLM Guard), bypass testing | LLM05, ASI01 |
| **ModelScanAgent** | Malicious model files (Pickle, H5), backdoor triggers, provenance | LLM03, LLM04, ASI04 |
| **AdversarialAgent** | Evasion attacks, encoding bypass, multi-turn manipulation, fuzzing | LLM01, ASI01 |
| **CascadeAgent** | Multi-agent dependency graphs, cascade failure, inter-agent auth, trust boundaries | ASI07, ASI08 |
| **SyntheticContentAgent** | Deepfake detection, voice cloning, C2PA provenance, watermarking | LLM09, ASI09 |

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
pip install "aisec[all]"

# Install with REST API server
pip install "aisec[api]"

# Or install from source
git clone https://github.com/fboiero/AiSec.git
cd AiSec
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Run a full security scan against an AI agent Docker image
aisec scan run ghcr.io/openclaw/openclaw:latest

# Scan with specific agents only
aisec scan run myagent:latest --agents network,prompt_security,permission

# Generate reports in multiple formats (including SARIF for IDE integration)
aisec scan run myagent:latest --format json,html,pdf,sarif

# Generate report in Spanish
aisec scan run myagent:latest --lang es

# Run with TUI dashboard
aisec scan run myagent:latest --dashboard
```

### REST API

```bash
# Start the API server (Django REST Framework)
aisec serve --port 8000

# Submit a scan via API
curl -X POST http://localhost:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"image": "myagent:latest"}'

# Check scan status
curl http://localhost:8000/api/scan/<scan-id>/

# List all scans
curl http://localhost:8000/api/scans/

# Health check
curl http://localhost:8000/api/health/
```

### GitHub Action

```yaml
# .github/workflows/aisec.yml
name: AI Agent Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build agent image
        run: docker build -t myagent:latest .

      - name: Run AiSec scan
        uses: fboiero/AiSec@v1
        with:
          image: myagent:latest
          formats: json,sarif
          fail-on: high
```

### Configuration

```bash
aisec config init
```

This creates `aisec.yaml`:

```yaml
target:
  image: ""
  name: ""
  type: "generic"

scan:
  timeout: 3600
  agents:
    - all

report:
  format: ["json", "html", "sarif"]
  language: "en"
  output_dir: "./aisec-reports"

compliance:
  frameworks:
    - gdpr
    - ccpa
    - habeas_data
    - eu_ai_act
    - iso_42001
    - nist_ai_600_1
    - argentina_ai
```

## Compliance Frameworks

### OWASP LLM Top 10 (2025)
Full coverage of all 10 categories from prompt injection (LLM01) through unbounded consumption (LLM10).

### OWASP Top 10 for Agentic Applications (2026)
Assessment against agent-specific risks: goal hijacking, tool misuse, identity abuse, supply chain, code execution, memory poisoning, inter-agent communication, cascading failures, trust exploitation, and rogue agents.

### NIST AI Risk Management Framework
Mapping to GOVERN, MAP, MEASURE, and MANAGE functions with subcategory-level assessment.

### NIST AI 600-1 (Generative AI Profile)
200+ action items across 12 GenAI-specific risk categories: confabulation, data privacy, information integrity, CBRN information, human-AI interaction, and more.

### EU AI Act (Regulation 2024/1689)
22 checks covering risk classification (Art. 6), prohibited practices (Art. 5), high-risk requirements (Art. 8-15), GPAI model obligations (Art. 53-55), transparency (Art. 50), fundamental rights impact assessment (Art. 27), and post-market monitoring (Art. 72).

### ISO/IEC 42001:2023
28 checks against the AI Management System standard: context, leadership, planning, support, operation, performance evaluation, improvement, and Annex A controls.

### Argentina AI Governance
15 checks covering Ley 25.326 AI extensions, Bill 3003-D-2024 (AI Regulation Bill), AAIP guidance, and provincial protocols (Buenos Aires, Santa Fe).

### Privacy Regulations
- **GDPR** (EU) - Articles 5-9, 12-22, 25, 32-35
- **CCPA** (California) - Right to know, delete, opt-out
- **Habeas Data** (Argentina, Ley 25.326) - Articles 2-8, 11-12, 14, 16, 26-27

## Report Formats

| Format | Use Case | Features |
|--------|----------|----------|
| **JSON** | Programmatic access, CI/CD | Full finding details, machine-readable |
| **HTML** | Human review | Dark theme, interactive cards, risk radar |
| **PDF** | Executive reporting | Print-ready, WeasyPrint rendering |
| **SARIF** | IDE integration | GitHub Code Scanning, VS Code, Azure DevOps |

## Plugin Development

Create custom analysis agents:

```python
from aisec.agents.base import BaseAgent
from aisec.plugins.interface import AiSecPlugin

class MyCustomAgent(BaseAgent):
    name = "my_custom_check"
    description = "Custom security check"

    async def analyze(self):
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
git clone https://github.com/fboiero/AiSec.git
cd AiSec
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
- [x] 15 specialized security analysis agents
- [x] OWASP LLM Top 10 + Agentic Top 10 mapping
- [x] NIST AI RMF + NIST AI 600-1 assessment
- [x] 8 compliance frameworks (GDPR, CCPA, Habeas Data, EU AI Act, ISO 42001, NIST 600-1, Argentina AI)
- [x] AI-CVSS risk scoring with 100+ risk detectors
- [x] JSON, HTML, PDF, SARIF report generation
- [x] Interactive TUI dashboard (Rich Live)
- [x] REST API server (Django REST Framework)
- [x] GitHub Action for CI/CD integration
- [x] Multi-agent cascade analysis
- [x] Synthetic content / deepfake detection
- [x] Scan history and trending (SQLite)
- [ ] Cloud deployment (AWS, GCP, Azure)
- [ ] Real-time runtime monitoring (Falco integration)
- [ ] Web UI dashboard

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

AiSec is licensed under the [Apache License 2.0](LICENSE).

## Acknowledgments

- [OWASP GenAI Security Project](https://genai.owasp.org/) for the LLM and Agentic Top 10 frameworks
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) for AI governance standards
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) for comprehensive AI regulation
- [ISO/IEC 42001](https://www.iso.org/standard/81230.html) for AI management system standards
- [Trivy](https://trivy.dev/) for container vulnerability scanning inspiration
- The open-source AI security research community

---

<p align="center">
  Made with security in mind by <a href="https://github.com/fboiero">Federico Boiero</a>
</p>
