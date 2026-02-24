# Changelog

All notable changes to AiSec are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-02-24

### Added
- **Prometheus Metrics** (`src/aisec/core/metrics.py`) — Production-grade observability with Prometheus-compatible `/api/metrics/` endpoint:
  - Counters: `aisec_scans_total` (by status), `aisec_findings_total` (by severity), `aisec_api_requests_total` (by method/endpoint/status)
  - Gauges: `aisec_scans_active` (currently running scans)
  - Histograms: `aisec_scan_duration_seconds`, `aisec_agent_duration_seconds` (by agent), `aisec_api_request_duration_seconds` (by method/endpoint)
  - No-op fallback when `prometheus_client` is not installed
  - New `[metrics]` extras group: `pip install aisec[metrics]`
- **Structured JSON Logging** — Replaced basic `logging.Formatter` with `structlog`-based processing chain:
  - JSON output via `AISEC_LOG_FORMAT=json` or `AISEC_LOG_JSON=true`
  - Human-readable console output by default
  - Request ID injection via `bind_context(request_id=...)` for API traceability
  - `X-Request-ID` header in all API responses
- **Scan Scheduler** (`src/aisec/core/scheduler.py`) — APScheduler-based recurring scan scheduler:
  - Cron expression support: `0 2 * * *` (daily at 2am), `@hourly`, `@daily`, `@weekly`, `@monthly`
  - API endpoints: `POST /api/schedules/`, `GET /api/schedules/`, `DELETE /api/schedules/{id}/`
  - CLI flags: `aisec serve --schedule "0 2 * * *" --schedule-image myapp:latest`
  - New `[scheduler]` extras group: `pip install aisec[scheduler]`
- **`.dockerignore`** — Excludes `.git/`, `tests/`, `__pycache__/`, `.github/`, `docs/`, `.claude/`, `deploy/` from Docker build context
- **3 new AiSecConfig fields**: `log_format`, `schedule_cron`, `schedule_image`
- ~26 new tests across 3 test files: metrics (14 tests), scheduler (12 tests), structured logging (10 tests)

### Changed
- Version bumped to 1.8.0
- `pyproject.toml`: added `[metrics]` (prometheus_client) and `[scheduler]` (apscheduler) extras groups, included in `[all]`
- `utils/logging.py` rewritten with structlog processors (backward-compatible `setup_logging("INFO")` call signature preserved)
- `serve.py`: instrumented with request metrics, request ID middleware, metrics/schedules endpoints
- `scan.py`: instrumented with scan/agent/finding metrics recording

## [1.8.0] - 2026-02-24

### Added
- **Prometheus Observability** (`src/aisec/core/metrics.py`) — Production-grade metrics via `prometheus_client`:
  - Counters: `aisec_scans_total`, `aisec_findings_total` (by severity), `aisec_api_requests_total` (by method/endpoint/status)
  - Gauges: `aisec_scans_active` (currently running scans)
  - Histograms: `aisec_scan_duration_seconds`, `aisec_agent_duration_seconds`, `aisec_api_request_duration_seconds`
  - `GET /api/metrics/` endpoint exposing Prometheus text format
  - No-op fallback when `prometheus_client` is not installed
  - New `[metrics]` extras group: `pip install aisec[metrics]`
- **Structured JSON Logging** — Rewrote `utils/logging.py` with structlog processors:
  - JSON output via `AISEC_LOG_FORMAT=json` or `AISEC_LOG_JSON=true` environment variables
  - Human-readable console output by default (structlog `ConsoleRenderer`)
  - Request ID injection via `bind_context(request_id=...)` for API traceability
  - `X-Request-ID` header propagation in API responses
  - Backward-compatible `setup_logging("INFO")` call signature
- **Scan Scheduler** (`src/aisec/core/scheduler.py`) — APScheduler-based recurring scans:
  - Cron expression support: `"0 2 * * *"` (daily at 2am), `@hourly`, `@daily`, `@weekly`, `@monthly`
  - API endpoints: `POST /api/schedules/`, `GET /api/schedules/`, `DELETE /api/schedules/{id}/`
  - CLI flags: `aisec serve --schedule "0 2 * * *" --schedule-image myapp:latest`
  - Schedule CRUD with run tracking (last_run, run_count)
  - New `[scheduler]` extras group: `pip install aisec[scheduler]`
- **`.dockerignore`** — Excludes `.git/`, `tests/`, `__pycache__/`, `.github/`, `docs/`, `.claude/`, `deploy/`, `*.md` (except README) from Docker build context
- **API instrumentation** — CorsMiddleware now records per-request metrics (method, endpoint, status, duration) and injects/propagates `X-Request-ID` header
- **3 new config fields**: `log_format`, `schedule_cron`, `schedule_image`
- ~26 new tests across 3 test files: metrics, scheduler, structured logging

### Changed
- Version bumped to 1.8.0
- `pyproject.toml`: added `[metrics]` and `[scheduler]` extras groups, included in `[all]`
- `structlog` (already in dependencies) now actively used for all logging
- Scan CLI and API server instrumented with Prometheus metrics

## [1.7.0] - 2026-02-23

### Added
- **Cloud Deployment** — Production-ready deployment manifests for Kubernetes, Helm, and Docker Compose:
  - 7 Kubernetes manifests: Deployment (2 replicas, health probes), Service, ConfigMap, Secret, Ingress (TLS), PVC, RBAC
  - Helm chart with customisable `values.yaml` (replicas, resources, image, storage, ingress, Falco toggle)
  - `docker-compose.prod.yml` with AiSec API + Nginx reverse proxy
  - Deployment guide (`deploy/README.md`) with quickstart for K8s, Helm, and Compose
- **Cloud Storage Module** (`src/aisec/core/cloud_storage.py`) — Upload scan reports to S3, GCS, or Azure Blob Storage:
  - Abstract `CloudStorageBackend` with concrete `S3Backend`, `GCSBackend`, `AzureBlobBackend`
  - Factory function `get_storage_backend(config)` for config-driven backend selection
  - New `[cloud]` extras group: `pip install aisec[cloud]` (boto3, google-cloud-storage, azure-storage-blob)
  - `--cloud-storage` CLI flag on `aisec scan` for automatic report upload
- **Falco Runtime Monitoring Agent** (`falco_runtime`) — 35th agent for eBPF-based syscall monitoring:
  - Deploys Falco as a PID-namespace-sharing sidecar container during sandbox execution
  - 9 custom AI/ML Falco rules: model file tampering, GPU access, prompt injection via env, crypto mining, DNS exfiltration, unauthorized model download, container escape, reverse shell, training data access
  - `FalcoAlertParser` for JSON alert parsing with OWASP LLM/Agentic framework mapping
  - Static checks: model files in /tmp, suspicious process detection
- **DockerManager.deploy_sidecar()** — Generic sidecar deployment with PID namespace sharing, volume mounts, and network integration (uses existing `SandboxInfo.sidecars` field)
- **5 new correlation rules** (31 total): Falco + network (active exploitation), Falco + permissions (model poisoning), Falco + dataflow (data breach), Falco + resource exhaustion (cryptojacking), Falco + privileged mode (full compromise)
- **5 new AiSecConfig fields**: `cloud_storage_backend`, `cloud_storage_bucket`, `cloud_storage_prefix`, `falco_enabled`, `falco_image`
- ~61 new tests across 5 test files: cloud storage, Falco agent, alert parser, deploy manifests, correlation rules

### Changed
- Version bumped to 1.7.0
- Agent count: 34 → 35
- Correlation rules: 26 → 31
- `pyproject.toml`: added `[cloud]` extras group, included in `[all]`

## [1.6.0] - 2026-02-23

### Added
- **Web UI Dashboard** (`src/aisec/dashboard/`) -- Interactive web interface served at `/dashboard/` when running `aisec serve`. Features include:
  - Home page with summary cards, severity distribution donut chart (Chart.js), findings trend line chart, and recent scans table
  - Paginated/filterable scan list with HTMX partial reload
  - Detailed scan view with Alpine.js tabbed interface (Summary, Findings, By Agent, Compliance tabs)
  - Global findings explorer with severity/agent/framework/status filters and HTMX-powered updates
  - Time-series trend charts showing findings over time, risk scores, and per-target breakdowns
  - Policy management page displaying built-in (strict/moderate/permissive) and saved policies
  - Scan submission form with agent selection, language choice, and Docker image autocomplete
  - Real-time scan status polling via HTMX partials (2-second intervals)
  - Dark theme using existing CSS variables from report templates
  - CDN-loaded Chart.js 4.x, Alpine.js 3.x, and HTMX 1.9.x (no new Python dependencies)
- `--dashboard/--no-dashboard` flag for `aisec serve` command (enabled by default)
- **5 new ScanHistory query methods**: `severity_distribution()`, `search_findings()`, `global_trend()`, `distinct_targets()`, `count_scans()`
- Automatic SQLite persistence of scan results in `_run_scan_in_thread()` (API scans now saved to history)
- Django TEMPLATES configuration and CSRF middleware support for dashboard views
- Dashboard context processor providing version, navigation, and active scan count to all templates
- 25 new tests in `test_web_dashboard.py` covering URL resolution, ScanHistory methods, context processors, and imports

### Changed
- Version bumped to 1.6.0.
- `serve.py` updated with dashboard URL routing, template configuration, and save_scan integration.

## [1.5.0] - 2026-02-23

### Added
- **RAGSecurityAgent** (29th agent) -- RAG pipeline security: unvalidated document loaders, missing retrieval filtering, context window stuffing, document injection via user-controlled paths, chunk validation gaps, hardcoded embedding API keys, retrieval poisoning through shared collections, and output grounding verification.
- **MCPSecurityAgent** (30th agent) -- Model Context Protocol server security: unauthenticated servers, overly permissive tool schemas, unrestricted tool access, insecure HTTP transport without TLS, missing rate limiting, sensitive tools without approval flows, resource URI path traversal, tool output sanitization, secrets in MCP configs, and debug endpoint exposure.
- **ToolChainSecurityAgent** (31st agent) -- Function calling and tool chain security: code execution without sandbox, file system tools without path restrictions, network tools without URL allowlists, SQL injection in tool functions, tool output → prompt injection, unrestricted chain execution, missing error handling, privileged tools without authentication, dangerous tool descriptions, and tool call audit trails.
- **AgentMemorySecurityAgent** (32nd agent) -- Agent memory and conversation persistence security: unencrypted memory stores, missing access controls, memory poisoning vectors, unbounded memory growth, cross-session data leakage, PII in persistent memory, memory injection via tool outputs, unsafe pickle serialization, and memory audit trail verification.
- **FineTuningSecurityAgent** (33rd agent) -- Fine-tuning pipeline security: unvalidated training data sources, training data PII exposure, missing deduplication, unsafe checkpoint storage, training secrets in configs, absent data provenance tracking, RLHF reward hacking patterns, unprotected model registries, untrusted web-scraped training data, and reproducibility gaps.
- **CICDPipelineSecurityAgent** (34th agent) -- CI/CD pipeline security for AI/ML: secrets in workflow configs, insecure model downloads without checksums, missing model signing, unsafe pip install flags, exposed training infrastructure, unprotected model artifacts, absent vulnerability scanning, Docker privileged mode in CI, unversioned model deployments, and missing branch protections.
- **Auto-Remediation Engine** (`src/aisec/remediation/`) -- Generates structured, actionable fix suggestions for every finding with concrete code patches, CLI commands, framework-specific guidance, and priority ordering. Includes 16+ remediation strategies covering secrets, input validation, guardrails, deserialization, SQL injection, rate limiting, PII, containers, TLS, MCP, RAG, memory, CI/CD, tool sandboxing, and training data. Produces severity-prioritized remediation plans with quick-win identification and effort estimation.
- **Policy-as-Code Engine** (`src/aisec/policies/`) -- YAML-based security policies for CI/CD gating with configurable severity thresholds, agent-specific rules, required agent lists, compliance gates, and numeric limits. Three built-in policies: `strict` (zero tolerance), `moderate` (staging), `permissive` (development). Gate verdicts (pass/fail/warn) with exit codes for CI/CD integration.
- **8 new correlation rules** (26 total) -- Cross-agent compound risk detection: RAG injection + no validation = data exfiltration, MCP no auth + unrestricted tools = agent takeover, tool chain no sandbox + privileged = arbitrary RCE, memory poisoning + no encryption = persistent compromise, poisoned training + no validation = model backdoor, CI secrets + no signing = supply chain attack, RAG + embedding no auth = retrieval manipulation, fine-tuning PII + no consent = regulatory violation.

### Changed
- Agent count increased from 28 to 34.
- Correlation rules increased from 18 to 26.
- Version bumped to 1.5.0.

## [1.4.0] - 2026-02-22

### Added
- **TaintAnalysisAgent** (21st agent) -- AST-based source-to-sink taint tracking of untrusted data (LLM outputs, user input, tool results) flowing to dangerous functions (eval, exec, SQL, subprocess) without sanitization.
- **SerializationAgent** (22nd agent) -- Deep deserialization attack surface scanning across pickle, YAML, XML (XXE), JSON (jsonpickle), protobuf, msgpack, and model file formats with __reduce__ override detection.
- **GitHistorySecretsAgent** (23rd agent) -- Git commit history secret scanning via gitleaks integration with built-in regex fallback for API keys, private keys, connection strings, JWTs, and high-entropy strings.
- **DeepDependencyAgent** (24th agent) -- Transitive dependency analysis via pipdeptree, license compliance checking via pip-licenses, dependency confusion risk detection, and abandoned package flagging.
- **ResourceExhaustionAgent** (25th agent) -- ReDoS detection via catastrophic backtracking analysis, zip bomb detection, unbounded loop detection, missing HTTP timeouts, memory allocation bombs, and recursive function depth limits.
- **InterServiceSecurityAgent** (26th agent) -- Webhook HMAC verification checks, mTLS absence detection, message queue authentication (RabbitMQ, Kafka, Redis), gRPC reflection detection, callback URL validation, and Kubernetes NetworkPolicy checks.
- **DataLineagePrivacyAgent** (27th agent) -- PII flow tracking to LLM APIs, consent mechanism verification, right-to-erasure implementation checks, PII in logs detection, training data privacy, and audit trail verification with GDPR/CCPA mapping.
- **EmbeddingLeakageAgent** (28th agent) -- Vector DB authentication checks (ChromaDB, Pinecone, Weaviate, Milvus, Qdrant, FAISS), multi-tenant namespace isolation, training data memorization risks, embedding cache integrity, and embedding API exposure.
- **Shared taint engine** (`utils/taint.py`) -- Reusable AST-based taint propagation engine with configurable sources, sinks, and flow tracking used by TaintAnalysis and other agents.
- **10 new correlation rules** (18 total) -- Cross-agent compound risk detection: taint flow + eval = code injection, unsafe deserialization + open ports = RCE, git secrets + active credentials, transitive vulns + no SBOM, ReDoS + public API, no mTLS + PII flow, PII to LLM + no consent, embeddings + no auth, pickle + unpinned deps = model poisoning, webhook no HMAC + open port.

### Changed
- Agent count increased from 20 to 28.
- Correlation rules increased from 8 to 18.
- `pyproject.toml` extended with `deptree` optional dependency group (pipdeptree, pip-licenses).
- `all` extras group updated to include `deptree`.
- Version bumped to 1.4.0.

## [1.3.0] - 2026-02-22

### Added
- **StaticAnalysisAgent** (16th agent) -- Semgrep + Bandit static code security analysis with built-in pattern fallback for eval/exec on LLM output, subprocess shell injection, pickle deserialization, hardcoded API keys, unsafe YAML loading, and prompt template injection.
- **DependencyAuditAgent** (17th agent) -- pip-audit integration for CVE-level vulnerability detection, typosquatting detection against popular AI/ML packages (Levenshtein distance), known malicious package blocklist (~50 packages), and dependency pinning analysis.
- **APISecurityAgent** (18th agent) -- Nuclei-based endpoint scanning with custom AI templates, authentication bypass detection, rate limiting verification, CORS policy analysis, information disclosure checks, GraphQL introspection detection, and verbose error analysis.
- **IaCSecurityAgent** (19th agent) -- Checkov integration for Dockerfile/K8s manifest scanning with built-in checks for root user, :latest tags, secrets in ENV/ARG, missing HEALTHCHECK, sensitive port exposure, privileged containers, hostNetwork, missing resource limits, and missing securityContext.
- **RuntimeBehaviorAgent** (20th agent) -- Container runtime behavior monitoring including suspicious process detection (miners, reverse shells), sensitive filesystem modification tracking, external network connection analysis, resource usage anomaly detection, and root process enumeration.
- **Cross-agent correlation engine** (`core/correlation.py`) -- Identifies compound risks by cross-referencing findings from multiple agents (e.g., "hardcoded credential + open port = critical data leak"). 8 built-in correlation rules covering data leaks, prompt injection, container escape, unbounded consumption, unverifiable dependencies, blind exploitation, remote exploitation, and infrastructure compromise.
- **Custom AI security Semgrep rules** (`rules/ai_security.yaml`) -- 10 rules targeting AI anti-patterns: eval/exec on LLM output, unvalidated tool results, prompt template injection, unsafe pickle/torch model loading, missing rate limits on inference endpoints, hardcoded API keys (OpenAI, Anthropic, HuggingFace), and unsafe YAML loading.
- **Custom Nuclei templates** (`rules/nuclei/`) -- 4 templates for AI API security: unauthenticated inference endpoints, exposed debug/docs endpoints, model enumeration without auth, and publicly accessible metrics.
- `correlated_risks` field added to `ScanReport` model and rendered in JSON, HTML, and fallback template outputs.

### Changed
- Agent count increased from 15 to 20.
- `pyproject.toml` extended with `static`, `audit`, `iac`, and `nuclei` optional dependency groups.
- `all` extras group updated to include new dependency groups.
- Version bumped to 1.3.0.

## [1.2.0] - 2026-02-22

### Added
- **Presidio PII integration** -- Optional NLP-based PII detection in DataFlowAgent using Microsoft Presidio with confidence scoring, entity grouping, and automatic value masking. Graceful fallback when Presidio is not installed.
- **detect-secrets integration** -- Optional entropy-based secret scanning in DataFlowAgent using Yelp's detect-secrets library with plugin-based heuristic detection beyond regex patterns.
- **API authentication** -- Optional API key authentication for the REST API via `AISEC_API_KEY` environment variable. Supports `X-API-Key` header and `api_key` query parameter.
- **Rate limiting** -- Configurable per-IP sliding-window rate limiting via `AISEC_RATE_LIMIT` environment variable (e.g. `100/min`, `10/s`). Adds `X-RateLimit-Limit` and `X-RateLimit-Remaining` response headers.
- **Target profiles** -- 8 built-in scan profiles (`autogpt`, `crewai`, `langchain`, `llamaindex`, `openai_assistants`, `huggingface`, `full`, `quick`) with auto-detection from container contents and CLI `--profile` flag.
- **CORS middleware** -- Standalone CORS middleware for the REST API with rate-limit header injection.

### Changed
- Plugin development guide expanded from 58 lines to comprehensive 300+ line reference with architecture diagrams, full BaseAgent API reference, ScanContext reference, event system docs, compliance mapping tables, testing patterns, advanced examples, and debugging tips.
- DataFlowAgent now supports optional Presidio and detect-secrets integrations alongside existing regex-based detection.
- REST API `_configure_django()` dynamically configures authentication and throttling based on environment variables.

## [1.1.0] - 2026-02-21

### Added
- **Data Anonymization Verifier** (M2.4) -- 5 checks in PrivacyAgent: anonymization/pseudonymization implementation, re-identification risk via quasi-identifiers, k-anonymity assessment, data masking in logs, and PII in caches/temp files.
- **Model Theft & Extraction Detection** (M3.5) -- 5 checks in NetworkAgent: rate limiting on inference endpoints, query logging/monitoring, output perturbation mechanisms, API authentication on model endpoints, and model versioning/access control.
- **Membership Inference Risk Assessment** (M3.6) -- 5 checks in AdversarialAgent: memorization pattern detection, training data extraction risk, differential privacy evaluation, canary value detection, and privacy risk scoring.
- **Webhook notifications** -- REST API support for event-driven notifications on scan completion/failure with HMAC-SHA256 payload signing, event filtering, and webhook management endpoints.
- **Multi-target scanning** -- CLI `aisec scan run img1,img2,img3` and REST API `POST /api/scan/batch/` for scanning multiple images in a single invocation.
- **Baseline management** -- Save named baselines from scans, compare current scans against baselines to detect regressions, and track new/resolved findings.
- **Shared scan policies** -- Named configuration presets stored in SQLite for team-wide consistent scanning.

### Changed
- REST API extended with 3 new endpoints: `/api/scan/batch/`, `/api/webhooks/`, `/api/webhooks/{id}/`.
- `ScanHistory` extended with baselines and scan_policies tables plus management methods.

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

[1.8.0]: https://github.com/fboiero/AiSec/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/fboiero/AiSec/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/fboiero/AiSec/compare/v1.5.0...v1.6.0
[1.8.0]: https://github.com/fboiero/AiSec/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/fboiero/AiSec/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/fboiero/AiSec/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/fboiero/AiSec/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/fboiero/AiSec/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/fboiero/AiSec/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/fboiero/AiSec/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fboiero/AiSec/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fboiero/AiSec/compare/v0.4.0...v1.0.0
[0.4.0]: https://github.com/fboiero/AiSec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fboiero/AiSec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fboiero/AiSec/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fboiero/AiSec/releases/tag/v0.1.0
