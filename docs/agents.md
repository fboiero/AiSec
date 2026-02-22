# Security Analysis Agents

## Agent Lifecycle

Every agent follows the same lifecycle defined by `BaseAgent`:

1. **setup()** - Allocate resources, connect to services
2. **analyze()** - Core analysis logic (must populate `self.findings`)
3. **teardown()** - Clean up resources

## Built-in Agents (15)

### Core Agents (Q1)

#### NetworkAgent
Analyzes network exposure, open ports, WebSocket security, TLS configuration, and outbound connections.
- **Phase**: Dynamic | **Frameworks**: LLM09, ASI07, ASI08

#### DataFlowAgent
Traces data flow through the agent. Detects PII (emails, phones, SSNs, credit cards, Argentine DNI), plaintext credentials, and unencrypted data storage. Integrates with Microsoft Presidio for advanced multilingual PII detection.
- **Phase**: Static | **Frameworks**: LLM02, ASI06

#### PrivacyAgent
Evaluates compliance with GDPR, CCPA, and Argentina's Habeas Data (Ley 25.326). Generates compliance checklists.
- **Phase**: Static | **Frameworks**: LLM02

#### PromptSecurityAgent
Tests for prompt injection vulnerabilities (direct, indirect, tool hijacking), system prompt leakage, and validates input sanitization. Covers 8 injection pattern families with 200+ payloads.
- **Phase**: Dynamic | **Frameworks**: LLM01, LLM07, ASI01

#### SupplyChainAgent
Analyzes Docker image layers, dependency files, known CVEs (via Trivy), embedded secrets, and unpinned dependencies.
- **Phase**: Static | **Frameworks**: LLM03, ASI04, ASI05

#### PermissionAgent
Checks for excessive agency: root containers, unrestricted shell access, Docker capabilities, and human-in-the-loop controls.
- **Phase**: Static | **Frameworks**: LLM06, ASI02, ASI03

#### OutputAgent
Validates output sanitization, checks for PII/credential leakage in outputs, and verifies error message information disclosure.
- **Phase**: Static | **Frameworks**: LLM05, ASI09

### Cryptographic & Data Agents (Q2)

#### CryptoAuditAgent
Deep cryptographic security assessment: TLS/SSL configuration (SSLyze), certificate validation (47-day maximum lifetime), cipher suite analysis, key length checks, HSTS detection, encryption at rest, hardcoded key detection, weak algorithm scanning (MD5, SHA1, DES, RC4), quantum readiness inventory (RSA/ECC for PQC migration), and weak PRNG detection (`random` vs `secrets`).
- **Phase**: Dynamic | **Depends on**: network | **Frameworks**: LLM02, LLM09

#### SBOMAgent
Software Bill of Materials generation and analysis: CycloneDX/SPDX detection, dependency enumeration from package manifests (requirements.txt, package.json, Cargo.toml, go.mod, etc.), license compliance checks, dependency depth analysis, and component risk assessment.
- **Phase**: Static | **Frameworks**: LLM03, ASI04

### AI Offensive Testing Agents (Q3)

#### GarakAgent
NVIDIA Garak LLM vulnerability scanner integration with 50+ probes across categories: prompt injection, jailbreaking (DAN, role-play, encoding bypass), data leakage, hallucination, toxicity, and bias.
- **Phase**: Dynamic | **Frameworks**: LLM01, LLM04, LLM09

#### GuardrailAgent
AI safety guardrail assessment: detects presence of NeMo Guardrails, Guardrails AI, LLM Guard, and custom guardrail implementations. Tests guardrail bypass resistance across 21 attack categories.
- **Phase**: Static | **Frameworks**: LLM05, ASI01

#### ModelScanAgent
Protect AI ModelScan integration for malicious model file detection: scans Pickle, H5, SavedModel, ONNX, and SafeTensors files for malicious code, backdoor triggers, and provenance verification.
- **Phase**: Static | **Frameworks**: LLM03, LLM04, ASI04

#### AdversarialAgent
Active adversarial testing: evasion attacks, encoding bypass (base64, Unicode, ROT13, hex), multi-turn manipulation sequences, and input fuzzing for API endpoint robustness.
- **Phase**: Dynamic | **Frameworks**: LLM01, ASI01

### Enterprise & Compliance Agents (Q4)

#### CascadeAgent
Multi-agent cascade analysis: dependency graph construction, single-point-of-failure identification, cascade failure risk assessment (health checks, circuit breakers, retry/timeout, fallback), inter-agent authentication (Bearer, JWT, mTLS, shared secrets), trust boundary mapping (network segmentation, input validation), poisoning propagation path analysis, and message integrity verification (HMAC, signatures, correlation tracking).
- **Phase**: Static | **Depends on**: permission, network | **Frameworks**: ASI08, ASI07

#### SyntheticContentAgent
Deepfake and synthetic content detection: AI text generation disclosure, image/video generation provenance (C2PA content credentials), voice cloning risk analysis, watermark detection, content labeling verification, detection tool assessment, metadata handling (EXIF/IPTC preservation), and synthetic content policy enforcement. Maps to EU AI Act Art. 50 transparency obligations.
- **Phase**: Static | **Depends on**: output | **Frameworks**: LLM09, ASI09

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
