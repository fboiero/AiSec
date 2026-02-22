# Changelog

All notable changes to AiSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-21

### Added
- **SyntheticContentAgent** (15th agent) -- deepfake detection, voice cloning risk analysis, C2PA content provenance, watermark verification, content labeling, metadata handling, and policy enforcement.
- **CascadeAgent** (14th agent) -- multi-agent dependency graph analysis, single-point-of-failure detection, cascade failure risk assessment, inter-agent authentication verification, trust boundary mapping, poisoning propagation paths, and message integrity checks.
- **EU AI Act compliance engine** -- 22 checks covering risk classification (Art. 6), prohibited practices (Art. 5), high-risk requirements (Art. 8-15), GPAI obligations (Art. 53-55), transparency (Art. 50), FRIA (Art. 27), conformity (Art. 43), and post-market monitoring (Art. 72).
- **ISO/IEC 42001:2023 assessment** -- 28 checks against AI Management System standard clauses 4-10 and Annex A controls.
- **NIST AI 600-1 GenAI Profile** -- 12 risk categories with 200+ action items covering confabulation, data privacy, information integrity, CBRN access, human-AI interaction, and value chain risks.
- **Argentina AI Governance module** -- 15 checks covering Ley 25.326 AI extensions, Bill 3003-D-2024, AAIP guidance, and provincial protocols (Buenos Aires, Santa Fe).
- **SARIF v2.1.0 renderer** -- IDE and CI integration output format for GitHub Code Scanning, VS Code SARIF Viewer, and Azure DevOps.
- **REST API server** (`aisec serve`) -- Django REST Framework-based HTTP API with endpoints for scan submission, status polling, result retrieval, and health checks. Browsable API included.
- **GitHub Action** (`action.yml`) -- Marketplace action with SARIF upload to Code Scanning, configurable severity threshold, and artifact upload.
- **Scan history module** -- SQLite-backed persistent storage for tracking security posture over time, trend analysis, new/resolved finding comparison, and aggregate statistics.
- **GitLab CI template** for enterprise GitLab CI/CD integration.

### Changed
- Version bumped to 1.0.0 (Production/Stable).
- `ReportBuilder` refactored to use dedicated compliance evaluators for all 7 frameworks.
- `ComplianceReport` model extended with `eu_ai_act`, `iso_42001`, `nist_ai_600_1`, and `argentina_ai` fields.
- `ComplianceFramework` enum extended with 4 new framework values.
- API dependency changed from FastAPI to Django REST Framework.
- `pyproject.toml` classifier upgraded to "Development Status :: 5 - Production/Stable".

## [0.4.0] - 2026-02-20

### Added
- **GarakAgent** -- NVIDIA Garak LLM vulnerability scanner integration with 50+ probes for prompt injection, jailbreaking, data leakage, hallucination, toxicity, and bias.
- **GuardrailAgent** -- AI safety guardrail assessment detecting NeMo Guardrails, Guardrails AI, LLM Guard, and custom implementations.
- **ModelScanAgent** -- Protect AI ModelScan integration for malicious model file detection (Pickle, H5, SavedModel, SafeTensors), backdoor triggers, and provenance verification.
- **AdversarialAgent** -- Active adversarial testing with evasion attacks, encoding bypass (base64, Unicode, ROT13, hex), multi-turn manipulation sequences, and input fuzzing.

### Fixed
- Adversarial regex backreference and CLI scan command routing.
- Docker agents now use DockerManager API correctly with full container IDs and proper `find -size` syntax.

## [0.3.0] - 2026-02-19

### Added
- **CryptoAuditAgent** -- Deep cryptographic security assessment: TLS/SSL config (SSLyze), certificate validation (47-day max lifetime), cipher suite analysis, key length checks, HSTS detection, encryption at rest, hardcoded key detection, weak algorithm scanning (MD5, SHA1, DES, RC4), quantum readiness inventory, and weak PRNG detection.
- **SBOMAgent** -- Software Bill of Materials generation and analysis: CycloneDX/SPDX detection, dependency enumeration, license compliance checks, dependency depth analysis, and component risk assessment.
- **TUI Dashboard** -- Rich Live dashboard showing real-time scan progress, agent status with finding counts, and live finding stream.
- Enhanced DataFlowAgent with advanced PII detection capabilities.

## [0.2.0] - 2026-02-18

### Added
- Production-ready scan engine with end-to-end scan pipeline.
- Full OWASP LLM Top 10 (2025) coverage across all 10 categories.
- Full OWASP Agentic Top 10 (2026) coverage across all 10 categories.
- NIST AI RMF mapping to GOVERN, MAP, MEASURE, and MANAGE functions.
- Compliance checklists for GDPR, CCPA, and Habeas Data (Ley 25.326).
- JSON, HTML (dark theme), and PDF report generation.
- Executive summary with risk radar chart.
- AI-CVSS scoring with 5 AI-specific risk dimensions.
- Plugin system with entry-point discovery.
- Spanish language support for reports.

## [0.1.0] - 2026-02-17

### Added
- Initial release of AiSec framework.
- 7 core security analysis agents: NetworkAgent, DataFlowAgent, PrivacyAgent, PromptSecurityAgent, SupplyChainAgent, PermissionAgent, OutputAgent.
- Docker-based sandboxing with network capture (tcpdump) and filesystem monitoring.
- Agent orchestrator with DAG-based dependency resolution.
- OWASP LLM Top 10 and Agentic Top 10 framework mapping.
- JSON report generation with finding details.
- Plugin architecture with entry-point registration.
- CLI interface: `aisec scan`, `aisec report`, `aisec config`, `aisec plugins`.
- Apache 2.0 license.

[1.0.0]: https://github.com/fboiero/AiSec/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/fboiero/AiSec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fboiero/AiSec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fboiero/AiSec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fboiero/AiSec/releases/tag/v0.1.0
