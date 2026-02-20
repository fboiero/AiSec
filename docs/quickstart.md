# Quick Start Guide

## Installation

```bash
pip install aisec
```

For all optional dependencies (PDF reports, network analysis, secret detection):

```bash
pip install aisec[all]
```

## Prerequisites

- Python 3.11+
- Docker Engine running locally
- (Optional) Trivy for enhanced CVE scanning

## Your First Scan

```bash
# Scan an AI agent Docker image
aisec scan ghcr.io/openclaw/openclaw:latest

# With specific agents
aisec scan myagent:latest --agents network,permission,prompt_security

# Generate HTML and PDF reports
aisec scan myagent:latest --format json,html,pdf

# Spanish report
aisec scan myagent:latest --lang es

# Custom config
aisec config init
# Edit aisec.yaml, then:
aisec scan myagent:latest --config aisec.yaml
```

## Understanding Results

AiSec produces findings categorized by:

- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Framework**: OWASP LLM Top 10, OWASP Agentic Top 10, NIST AI RMF
- **Compliance**: GDPR, CCPA, Habeas Data

Each finding includes evidence, an AI-CVSS risk score, and remediation steps.

## Next Steps

- Read the [Architecture](architecture.md) documentation
- Learn about [Agent Development](agents.md)
- Explore [Plugin Development](plugin-development.md)
