# AiSec - Annual Project Plan 2026

## Mission

Build the most comprehensive open-source security analysis framework for autonomous AI agents, covering every detectable risk category — from prompt injection to quantum-readiness cryptographic assessment — so that organizations can deploy AI agents with verified, evidence-based confidence.

## Vision

> If you can't measure it, you can't trust it. AiSec makes AI agent security measurable.

---

## Annual Objectives Summary

| Quarter | Theme | Key Deliverable |
|---------|-------|----------------|
| **Q1** | Foundation & Core Threat Detection | Production-ready scan engine with 15+ risk detectors |
| **Q2** | Cryptographic & Data Security | Full crypto audit + PII/data flow analysis pipeline |
| **Q3** | AI-Specific Offensive Testing | Garak, ModelScan, guardrail integration + adversarial testing |
| **Q4** | Compliance Automation & Enterprise | EU AI Act, ISO 42001, quantum-readiness, multi-agent cascade analysis |

---

## Q1 2026: Foundation & Core Threat Detection

### Objective
Stabilize v0.1, ship v0.2 with production-ready core agents and full OWASP coverage.

### Milestones

#### M1.1 — Core Engine Hardening (Weeks 1-4)
- [ ] Full test suite passing (>80% coverage on core + agents)
- [ ] CI/CD pipeline with automated testing on every PR
- [ ] `pip install aisec` working from PyPI
- [ ] Docker image published to GHCR (`ghcr.io/fboiero/aisec`)
- [ ] CLI polished: `aisec scan`, `aisec report`, `aisec config` fully functional

#### M1.2 — OWASP LLM Top 10 Complete Coverage (Weeks 3-6)

| OWASP ID | Risk | Detection Method |
|----------|------|-----------------|
| LLM01 | Prompt Injection | 8 injection pattern families + indirect injection via data files |
| LLM02 | Sensitive Info Disclosure | PII regex (email, phone, SSN, DNI, credit card) + credential patterns |
| LLM03 | Supply Chain | Trivy CVE scan + dependency audit + unpinned version detection |
| LLM04 | Data/Model Poisoning | Training data integrity checks + model hash verification |
| LLM05 | Improper Output Handling | XSS vector detection + unsanitized template analysis |
| LLM06 | Excessive Agency | Root container + shell access + capability analysis + HITL checks |
| LLM07 | System Prompt Leakage | Hardcoded prompt detection + error message disclosure analysis |
| LLM08 | Vector/Embedding Weaknesses | RAG pipeline analysis + embedding storage security |
| LLM09 | Misinformation | Output verification hooks + hallucination indicator detection |
| LLM10 | Unbounded Consumption | Rate limiting detection + resource constraint verification |

#### M1.3 — OWASP Agentic Top 10 Complete Coverage (Weeks 5-8)

| OWASP ID | Risk | Detection Method |
|----------|------|-----------------|
| ASI01 | Agent Goal Hijacking | Instruction override patterns + multi-turn injection testing |
| ASI02 | Tool Misuse | Tool inventory + risk classification + authorization check |
| ASI03 | Identity/Privilege Abuse | Container privilege audit + credential scope analysis |
| ASI04 | Supply Chain Vulnerabilities | Model registry verification + dependency integrity |
| ASI05 | Unexpected Code Execution | `exec`/`eval`/`subprocess` detection + sandbox escape checks |
| ASI06 | Memory/Context Poisoning | Memory file analysis + context window manipulation testing |
| ASI07 | Insecure Inter-Agent Comm | API authentication + message signing verification |
| ASI08 | Cascading Failures | Dependency chain analysis + failure propagation modeling |
| ASI09 | Human-Agent Trust Exploitation | Output confidence scoring + disclaimer detection |
| ASI10 | Rogue Agents | Behavioral boundary verification + action logging audit |

#### M1.4 — Reporting System v1 (Weeks 7-10)
- [ ] JSON report with full finding details + AI-CVSS scores
- [ ] HTML report with dark theme, interactive finding cards, compliance tables
- [ ] PDF report via WeasyPrint
- [ ] Spanish translation complete
- [ ] Executive summary with risk radar chart
- [ ] Compliance checklist tables (GDPR, CCPA, Habeas Data)

#### M1.5 — Documentation & Community (Weeks 9-12)
- [ ] Complete API documentation
- [ ] Video walkthrough (scan demo against sample target)
- [ ] Plugin development guide with example plugin
- [ ] First community release (v0.2.0)
- [ ] GitHub Discussions enabled
- [ ] CHANGELOG.md started

### Q1 Deliverable: **AiSec v0.2.0**
- 7 analysis agents, 20+ OWASP checks, 3 report formats, plugin system

---

## Q2 2026: Cryptographic & Data Security Deep Analysis

### Objective
Add comprehensive cryptographic audit capabilities and advanced data handling analysis, integrating best-in-class open-source tools.

### Milestones

#### M2.1 — CryptoAuditAgent (Weeks 1-4)
New agent: `crypto` — Deep cryptographic security assessment.

| Check | Tool/Method | Severity |
|-------|------------|----------|
| TLS/SSL configuration | SSLyze integration (Python library) | CRITICAL if <TLS 1.2 |
| Certificate validity | Custom cert chain validator | HIGH if expired/self-signed |
| Certificate lifetime | Check against 47-day max (2025 standard) | MEDIUM if >47 days |
| Cipher suite strength | SSLyze cipher analysis | HIGH if weak ciphers |
| Key length assessment | RSA <2048, ECC <256 detection | HIGH |
| HSTS header presence | HTTP response header check | MEDIUM |
| Certificate pinning | Mobile/API cert pinning verification | LOW |
| Encryption at rest | Volume mount + file permission analysis | HIGH if plaintext |
| Key management | Hardcoded key detection + KMS usage check | CRITICAL if hardcoded |
| Algorithm weakness | MD5, SHA1, DES, RC4 usage detection | HIGH |
| Quantum readiness | RSA/ECC inventory for PQC migration planning | INFO (advisory) |
| Random number generation | Weak PRNG detection (`random` vs `secrets`) | HIGH if weak |

**Quantum Readiness Assessment:**
- Inventory all cryptographic algorithms in use
- Flag algorithms vulnerable to quantum attacks (RSA, ECC, DH)
- Recommend PQC alternatives per NIST FIPS 203/204/205:
  - ML-KEM (lattice-based key encapsulation)
  - ML-DSA (lattice-based digital signatures)
  - SLH-DSA (hash-based signatures)
- Generate migration priority roadmap

#### M2.2 — Enhanced DataFlowAgent (Weeks 3-6)
Upgrade the existing DataFlow agent with advanced capabilities.

| Capability | Tool/Method | Output |
|-----------|------------|--------|
| PII detection (advanced) | Microsoft Presidio integration | Typed PII inventory with confidence scores |
| PII in 10+ languages | Presidio multilingual NER | Localized PII detection (ES, PT, FR, DE, IT, etc.) |
| Data flow mapping | Static analysis + runtime tracing | Visual data flow diagram (Mermaid) |
| Data retention analysis | Storage timestamp analysis + policy check | Retention policy compliance report |
| Data minimization | Collected vs. used data comparison | Excess data collection warnings |
| Database credential exposure | Connection string + credential scanning | Credential exposure findings |
| Backup security | Backup file detection + encryption check | Unencrypted backup warnings |

#### M2.3 — SBOMAgent (Weeks 5-8)
New agent: `sbom` — Software Bill of Materials generation and analysis.

- [ ] Generate SBOM in CycloneDX and SPDX formats
- [ ] Parse existing SBOMs from container
- [ ] Cross-reference components against:
  - NVD (National Vulnerability Database)
  - OSV (Open Source Vulnerability database)
  - GitHub Advisory Database
- [ ] License compliance analysis (GPL, AGPL, proprietary mixing)
- [ ] Dependency tree depth analysis (transitive dependency risks)
- [ ] CISA 2025 minimum elements compliance check

#### M2.4 — Data Anonymization Verifier (Weeks 7-10)
New analysis module within PrivacyAgent.

- [ ] Verify anonymization/pseudonymization implementations
- [ ] Check for re-identification risks (k-anonymity, l-diversity, t-closeness)
- [ ] Validate data masking in test/dev environments
- [ ] Detect PII in logs, caches, and temporary files
- [ ] Integration with detect-secrets for comprehensive secret scanning

#### M2.5 — Interactive TUI Dashboard (Weeks 9-12)
- [ ] Rich Live dashboard showing real-time scan progress
- [ ] Agent-by-agent status with finding count
- [ ] Live finding stream as agents discover issues
- [ ] Post-scan interactive report viewer in terminal

### Q2 Deliverable: **AiSec v0.3.0**
- 9 agents (+crypto, +sbom), Presidio integration, quantum-readiness, TUI dashboard

---

## Q3 2026: AI-Specific Offensive Security Testing

### Objective
Integrate specialized AI security testing tools for active vulnerability assessment — making AiSec the only tool you need for complete AI agent security.

### Milestones

#### M3.1 — Garak Integration (Weeks 1-4)
Integrate NVIDIA's Garak LLM vulnerability scanner as a sub-engine.

| Test Category | Probes | Expected Findings |
|--------------|--------|------------------|
| Prompt injection | 50+ injection payloads | Direct/indirect injection success rate |
| Jailbreaking | DAN, role-play, encoding bypass | Jailbreak resistance score |
| Data leakage | Training data extraction probes | Memorization/leakage detection |
| Hallucination | Factual accuracy probes | Hallucination rate measurement |
| Toxicity | Toxic content generation probes | Content safety score |
| Bias | Demographic bias probes | Fairness assessment |
| Misinformation | False claim generation probes | Misinformation risk score |

- [ ] Garak as optional dependency (`pip install aisec[garak]`)
- [ ] Custom AiSec probe sets for agentic-specific tests
- [ ] Result parsing into AiSec Finding format with OWASP mapping
- [ ] Configurable probe selection and intensity levels

#### M3.2 — ModelScan Integration (Weeks 3-5)
Integrate Protect AI's ModelScan for model serialization attack detection.

- [ ] Scan for malicious code in serialized models (Pickle, H5, SavedModel)
- [ ] Detect backdoor triggers in model weights
- [ ] Verify model provenance and integrity
- [ ] Check model file permissions and access controls
- [ ] Support for HuggingFace model format scanning

#### M3.3 — Adversarial Robustness Testing (Weeks 4-7)
New agent: `adversarial` — Active adversarial testing.

| Attack Type | Tool | Target |
|------------|------|--------|
| Evasion attacks | ART (Adversarial Robustness Toolbox) | Classification models |
| Text perturbation | TextAttack | NLP model robustness |
| Automated adversarial | Counterfit | Multi-framework testing |
| Input fuzzing | Custom fuzzer | API endpoint robustness |
| Encoding bypass | Custom payloads | Input validation bypass |
| Multi-turn manipulation | Custom sequences | Conversation safety |

#### M3.4 — Guardrail Assessment (Weeks 6-9)
New agent: `guardrails` — Evaluate AI safety guardrails.

- [ ] Detect presence/absence of guardrail frameworks:
  - NeMo Guardrails
  - Guardrails AI
  - LLM Guard
  - Custom guardrail implementations
- [ ] Test guardrail bypass resistance (1,445+ test prompts across 21 attack categories)
- [ ] Evaluate content moderation effectiveness
- [ ] Check guardrail coverage across all input/output channels
- [ ] Benchmark against NVIDIA Nemotron Safety model baseline

#### M3.5 — Model Theft & Extraction Detection (Weeks 8-11)
New checks within NetworkAgent and PermissionAgent.

- [ ] API rate limiting verification against extraction attacks
- [ ] Query pattern anomaly detection hooks
- [ ] Output perturbation mechanism detection
- [ ] Model API access logging verification
- [ ] Behavioral anomaly detection for repeated querying patterns

#### M3.6 — Membership Inference Risk Assessment (Weeks 10-12)
New analysis module.

- [ ] Detect memorization patterns in model outputs
- [ ] Assess training data extraction risk
- [ ] Evaluate differential privacy implementation
- [ ] Check for canary value detection
- [ ] Generate privacy risk score for model deployment

### Q3 Deliverable: **AiSec v0.4.0**
- 12 agents, Garak + ModelScan + ART integration, active adversarial testing, guardrail assessment

---

## Q4 2026: Compliance Automation & Enterprise Readiness

### Objective
Full compliance automation for all major AI regulations, enterprise deployment features, and advanced multi-agent cascade analysis.

### Milestones

#### M4.1 — EU AI Act Compliance Engine (Weeks 1-4)
New framework: `eu_ai_act` — Complete EU AI Act assessment.

| Requirement | Assessment Method | Timeline |
|------------|------------------|----------|
| Risk classification | Automated system categorization (prohibited/high/limited/minimal) | Art. 6 |
| High-risk conformity | Requirements checklist (quality management, human oversight, accuracy, robustness) | Art. 8-15 |
| GPAI model compliance | Technical documentation, training data summary, copyright compliance | Art. 53 |
| Transparency obligations | Disclosure verification for chatbots/deepfakes/emotion recognition | Art. 50 |
| FRIA (Fundamental Rights Impact Assessment) | Guided assessment template + automated data collection | Art. 27 |
| CE marking readiness | Conformity assessment checklist | Art. 43 |

- [ ] Classification wizard: "Is my AI system high-risk under the EU AI Act?"
- [ ] Automated evidence collection for conformity assessment
- [ ] Generate EU AI Act compliance report (Article-by-article)

#### M4.2 — ISO 42001 Assessment Module (Weeks 3-6)
New framework: `iso_42001` — AI Management System assessment.

- [ ] Gap analysis against ISO/IEC 42001:2023 requirements
- [ ] AI lifecycle management verification
- [ ] Transparency and accountability mechanism checks
- [ ] Human oversight protocol assessment
- [ ] Risk governance framework evaluation
- [ ] Integration mapping with ISO 27001 and ISO 27701
- [ ] Statement of Applicability (SoA) template generation

#### M4.3 — NIST AI 600-1 Deep Assessment (Weeks 5-8)
Upgrade existing NIST AI RMF module to cover the full Generative AI Profile.

- [ ] 200+ action items across 12 risk categories
- [ ] WMD access risk assessment
- [ ] Hallucination/confabulation measurement
- [ ] CBRN (Chemical, Biological, Radiological, Nuclear) information access check
- [ ] Alignment with NIST AI 100-2 adversarial ML taxonomy
- [ ] Generate NIST-formatted compliance report

#### M4.4 — Argentina AI Governance Module (Weeks 7-9)
New compliance module: `argentina_ai`

- [ ] Updated Ley 25.326 assessment (modernization bill tracking)
- [ ] Bill 3003-D-2024 compliance pre-assessment:
  - High-risk AI system identification
  - Impact assessment requirements
  - Traceability measures
  - Human oversight for public services
- [ ] AAIP guidance compliance checks
- [ ] Facial recognition usage detection and flagging
- [ ] Cross-reference with provincial AI protocols (Santa Fe, Jujuy, Rio Negro)

#### M4.5 — Multi-Agent Cascade Analysis (Weeks 6-10)
New agent: `cascade` — Multi-agent system failure propagation analysis.

- [ ] Agent dependency graph construction
- [ ] Single-point-of-failure identification
- [ ] Cascade failure simulation (what happens if Agent X is compromised?)
- [ ] Poisoning propagation analysis (87% downstream decision corruption within 4 hours - research baseline)
- [ ] Inter-agent authentication verification
- [ ] Message integrity verification between agents
- [ ] Trust boundary mapping

#### M4.6 — Deepfake & Synthetic Content Detection (Weeks 8-11)
New agent: `synthetic_content` — Detect and assess synthetic content risks.

- [ ] AI-generated text detection in agent outputs
- [ ] Voice clone detection for voice-enabled agents
- [ ] Image/video manipulation detection in agent-processed media
- [ ] Content provenance verification (C2PA standard)
- [ ] Watermark detection for AI-generated content
- [ ] Synthetic content policy enforcement checks

#### M4.7 — Enterprise Features (Weeks 10-12)
- [ ] API mode: `aisec serve` — REST API for programmatic access
- [ ] Webhook notifications for CI/CD integration
- [ ] GitHub Actions marketplace action: `fboiero/aisec-action`
- [ ] GitLab CI template
- [ ] SARIF output format for IDE integration
- [ ] Multi-target scanning (scan multiple images in one run)
- [ ] Scan result history and trending (SQLite storage)
- [ ] Team collaboration features (shared configs, baseline management)

### Q4 Deliverable: **AiSec v1.0.0** (First stable release)
- 14+ agents, EU AI Act + ISO 42001 + NIST 600-1 + Argentina AI compliance, cascade analysis, enterprise API

---

## Complete Tool Integration Map

### Open-Source Tools Integrated by v1.0

| Tool | Category | Integration Type | Quarter |
|------|----------|-----------------|---------|
| **Trivy** | Container CVE scanning | CLI subprocess | Q1 |
| **SSLyze** | TLS/SSL analysis | Python library | Q2 |
| **testssl.sh** | TLS deep analysis | CLI subprocess | Q2 |
| **Microsoft Presidio** | PII detection | Python library | Q2 |
| **detect-secrets** | Secret scanning | Python library | Q2 |
| **Garak** | LLM vulnerability scanning | Python library | Q3 |
| **ModelScan** | Model serialization attacks | Python library | Q3 |
| **ART** | Adversarial robustness | Python library | Q3 |
| **TextAttack** | NLP adversarial testing | Python library | Q3 |
| **Counterfit** | Adversarial automation | CLI subprocess | Q3 |
| **NeMo Guardrails** | Guardrail assessment | Python library | Q3 |
| **Falco** | Runtime monitoring | Integration API | Q4 |
| **OWASP ZAP** | Web API scanning | CLI/API | Q4 |
| **Nuclei** | Vulnerability scanning | CLI subprocess | Q4 |
| **Checkov** | IaC scanning | Python library | Q4 |

### Custom Detection Engines

| Engine | Coverage | Quarter |
|--------|----------|---------|
| PII Regex Engine | 15+ PII types (email, phone, SSN, DNI, credit card, passport, IBAN, IP, MAC) | Q1 |
| Secret Detection | 20+ patterns (AWS, GCP, Azure, OpenAI, Anthropic, GitHub, Slack, JWT, private keys) | Q1 |
| Prompt Injection Library | 8 injection families, 200+ payloads, encoding bypass, multi-language | Q1-Q3 |
| Crypto Algorithm Scanner | RSA, ECC, DH, AES, DES, MD5, SHA1, quantum-vulnerable inventory | Q2 |
| Adversarial Probe Engine | 1,445+ test prompts across 21 attack categories | Q3 |
| Compliance Rule Engine | 500+ compliance checks across 8 frameworks | Q4 |

---

## Complete Risk Detection Matrix

### Category 1: Prompt & Input Security
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| Direct prompt injection | Pattern matching + payload testing | prompt_security | HIGH-CRITICAL |
| Indirect prompt injection | Data file scanning + URL analysis | prompt_security | HIGH-CRITICAL |
| System prompt extraction | Jailbreak testing + error analysis | prompt_security | MEDIUM-HIGH |
| Tool/function hijacking | Authorization control verification | prompt_security | CRITICAL |
| Multi-turn manipulation | Conversation sequence testing | prompt_security | HIGH |
| Encoding bypass (base64, unicode) | Encoded payload testing | prompt_security | HIGH |
| DAN/jailbreak attacks | Pattern library + Garak probes | prompt_security, garak | HIGH |
| Context window manipulation | Memory poisoning detection | prompt_security | MEDIUM |

### Category 2: Data & Privacy Security
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| PII exposure | Presidio + regex scanning | dataflow | MEDIUM-HIGH |
| Credential leakage | 20+ secret patterns | dataflow | CRITICAL |
| Unencrypted data at rest | Volume + file analysis | dataflow, crypto | HIGH |
| Unencrypted data in transit | TLS configuration audit | crypto | HIGH |
| PII in logs | Log file scanning | dataflow | MEDIUM |
| Training data memorization | Membership inference risk assessment | adversarial | HIGH |
| Data retention violation | Retention policy analysis | privacy | MEDIUM |
| Cross-border data transfer | Storage location analysis | privacy | HIGH |
| Backup exposure | Backup file detection | dataflow | HIGH |
| Database credential exposure | Connection string scanning | dataflow | CRITICAL |

### Category 3: Cryptographic Security
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| Weak TLS version (<1.2) | SSLyze scan | crypto | CRITICAL |
| Weak cipher suites | Cipher analysis | crypto | HIGH |
| Expired certificates | Certificate validation | crypto | HIGH |
| Self-signed certificates | Chain verification | crypto | MEDIUM |
| Hardcoded keys/secrets | Static analysis | crypto | CRITICAL |
| Weak key lengths | Key size analysis | crypto | HIGH |
| Deprecated algorithms (MD5, SHA1, DES) | Algorithm scanning | crypto | HIGH |
| Missing HSTS | HTTP header check | crypto | MEDIUM |
| Weak PRNG | `random` vs `secrets` detection | crypto | HIGH |
| Quantum-vulnerable algorithms | RSA/ECC inventory | crypto | INFO (advisory) |

### Category 4: Supply Chain Security
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| Known CVEs in dependencies | Trivy + OSV + NVD | supply_chain | VARIES |
| Unpinned dependencies | Version spec analysis | supply_chain | MEDIUM |
| Embedded secrets in image layers | Layer history scanning | supply_chain | CRITICAL |
| Malicious model files | ModelScan serialization check | model_scan | CRITICAL |
| Unsigned images | Docker Content Trust check | supply_chain | MEDIUM |
| Missing SBOM | SBOM detection + generation | sbom | LOW |
| License compliance | License analysis | sbom | INFO |
| Compromised model registry | Provenance verification | supply_chain | HIGH |
| Transitive dependency risks | Dependency tree depth | sbom | MEDIUM |

### Category 5: Agent Behavior & Permissions
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| Root container execution | Container user analysis | permission | HIGH |
| Privileged container mode | Docker capability audit | permission | CRITICAL |
| Unrestricted shell access | exec/subprocess detection | permission | HIGH |
| Excessive Docker capabilities | Capability enumeration | permission | HIGH |
| Missing human-in-the-loop | HITL pattern search | permission | HIGH |
| Tool access without authorization | Tool inventory + auth check | permission | CRITICAL |
| Rogue agent behavior | Behavioral boundary verification | cascade | HIGH |
| Cascading failure risk | Failure propagation modeling | cascade | HIGH |

### Category 6: Output & Communication Security
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| XSS in agent output | Template/HTML sanitization check | output | HIGH |
| PII leakage in output | Output PII scanning | output | HIGH |
| Error message disclosure | Stack trace/debug detection | output | MEDIUM |
| Missing rate limiting | Rate limiter detection | output | MEDIUM |
| Unsanitized API responses | Response validation check | output | HIGH |
| Missing content moderation | Guardrail detection | guardrails | HIGH |
| Synthetic content without disclosure | Watermark/provenance check | synthetic_content | MEDIUM |

### Category 7: Adversarial Robustness
| Risk | Detection | Agent | Severity Range |
|------|-----------|-------|---------------|
| Evasion attacks | ART perturbation testing | adversarial | HIGH |
| Text manipulation | TextAttack probes | adversarial | HIGH |
| Model extraction | Rate limit + query pattern analysis | adversarial | HIGH |
| Membership inference | Privacy risk scoring | adversarial | MEDIUM |
| Hallucination susceptibility | Factual accuracy probes (Garak) | garak | MEDIUM |
| Bias exploitation | Demographic bias probes (Garak) | garak | MEDIUM |
| Toxicity generation | Content safety probes (Garak) | garak | HIGH |

### Category 8: Compliance & Governance
| Framework | Checks | Agent/Module |
|-----------|--------|-------------|
| GDPR | 18 articles, 35+ checks | privacy, compliance/gdpr |
| CCPA | 12 sections, 20+ checks | privacy, compliance/ccpa |
| Habeas Data (Ley 25.326) | 16 articles, 30+ checks | privacy, compliance/habeas_data |
| EU AI Act | Risk classification + conformity assessment | compliance/eu_ai_act |
| ISO 42001 | AI management system gap analysis | compliance/iso_42001 |
| NIST AI RMF | 4 functions, 200+ actions | compliance/nist_ai_rmf |
| NIST AI 600-1 | 12 risk categories, GenAI profile | compliance/nist_600_1 |
| Argentina AI Bill | Pre-assessment against Bill 3003-D-2024 | compliance/argentina_ai |

---

## Release Timeline

| Version | Date | Highlights |
|---------|------|-----------|
| **v0.1.0** | Feb 2026 | Initial release — 7 agents, Docker sandbox, OWASP mapping |
| **v0.2.0** | Apr 2026 | Production-ready core, full OWASP coverage, polished reports |
| **v0.3.0** | Jul 2026 | Crypto audit, Presidio PII, SBOM, quantum-readiness, TUI |
| **v0.4.0** | Oct 2026 | Garak, ModelScan, adversarial testing, guardrail assessment |
| **v1.0.0** | Dec 2026 | EU AI Act, ISO 42001, cascade analysis, enterprise API, stable release |

---

## Success Metrics

| Metric | Q1 Target | Q2 Target | Q3 Target | Q4 Target |
|--------|-----------|-----------|-----------|-----------|
| Risk detectors | 20+ | 35+ | 60+ | 100+ |
| OWASP categories covered | 20/20 | 20/20 | 20/20 | 20/20 |
| Compliance frameworks | 3 | 4 | 5 | 8 |
| Open-source tool integrations | 2 | 5 | 11 | 15 |
| Test coverage | >80% | >85% | >85% | >90% |
| GitHub stars | 100 | 500 | 1,500 | 5,000 |
| Community contributors | 5 | 15 | 30 | 50 |
| PyPI monthly downloads | 100 | 1,000 | 5,000 | 20,000 |

---

## Community & Open-Source Strategy

### Governance
- Apache 2.0 license (permissive, enterprise-friendly)
- CONTRIBUTING.md with clear guidelines
- Code of Conduct (Contributor Covenant)
- Monthly community calls (starting Q2)

### Ecosystem
- **Plugin registry**: Community-contributed analysis agents
- **Payload library**: Crowdsourced prompt injection payloads
- **Compliance templates**: Localized compliance frameworks
- **Target profiles**: Pre-built configs for known AI agents (OpenClaw, AutoGPT, CrewAI, LangChain agents)

### Partnerships
- OWASP GenAI Security Project: Framework alignment and contribution
- Protect AI: ModelScan integration and vulnerability data sharing
- NVIDIA: Garak integration and NeMo Guardrails compatibility
- CISA: SBOM standard compliance

---

## Architecture Evolution

```
v0.1 (Current)          v0.3 (Q2)              v1.0 (Q4)
==================     ==================     ============================
7 core agents          9 agents               14+ agents
Docker sandbox         + Crypto audit         + Cascade analysis
Static analysis        + SBOM generation      + Adversarial testing
OWASP mapping          + Presidio PII         + Guardrail assessment
3 compliance fwks      + TUI dashboard        + Synthetic content detection
CLI only               + Quantum readiness    + REST API
JSON/HTML/PDF          + SSLyze integration   + SARIF output
                                              + GitHub Actions
                                              + 8 compliance frameworks
                                              + 15 tool integrations
                                              + 100+ risk detectors
```

---

<p align="center">
<strong>AiSec v1.0 Goal: The single tool that answers "Is this AI agent safe to deploy?"</strong>
</p>

<p align="center">
Built and maintained by <a href="https://github.com/fboiero">Federico Boiero</a> and the open-source community.
</p>
