# AiSec Session Context

## Current Goal
v1.7.0 implementation complete — ready for commit and release.

## Plan
v1.7.0 — Cloud Deployment & Falco Runtime Monitoring (25 new files, 11 modified, ~61 tests).

## Completed
- **Cloud Deployment**: 7 K8s manifests, Helm chart (5 files), docker-compose.prod.yml, deploy/README.md
- **Cloud Storage Module** (`src/aisec/core/cloud_storage.py`): S3, GCS, Azure Blob backends with factory function
- **Falco Runtime Agent** (`falco_runtime`, 35th agent): eBPF sidecar deployment, alert parsing, 9 custom AI/ML rules
- **Falco Alert Parser** (`src/aisec/agents/falco_alert_parser.py`): JSON parsing, OWASP mapping, severity mapping
- **DockerManager.deploy_sidecar()**: Generic sidecar deployment with PID namespace sharing
- **5 new correlation rules** (31 total): Falco + network/permissions/dataflow/resource_exhaustion
- **5 new AiSecConfig fields**: cloud_storage_backend, cloud_storage_bucket, cloud_storage_prefix, falco_enabled, falco_image
- **`--cloud-storage` CLI flag** on `aisec scan` for automatic report upload
- **`[cloud]` extras group** in pyproject.toml (boto3, google-cloud-storage, azure-storage-blob)
- **Version bumped** to 1.7.0 in __init__.py and pyproject.toml
- **CHANGELOG.md** updated with v1.7.0 entry
- **README.md** updated: 35 agents, 31 rules, Layer 5 architecture, cloud/Falco sections, roadmap checkboxes
- **5 test files** (~61 tests): cloud_storage, falco_agent, alert_parser, deploy_manifests, correlation_v17
- **All 1346 tests pass** (12 skipped — Django-related)

## Pending
- Git commit, tag, push, GitHub release for v1.7.0

## Key Decisions
- Cloud storage backends use optional SDK imports (boto3, google-cloud-storage, azure-storage-blob) — graceful ImportError
- Falco uses falco-no-driver image (eBPF userspace) — no kernel module required
- Falco sidecar shares PID namespace with target container for syscall visibility
- deploy_sidecar() is generic (not Falco-specific) for future sidecar use cases
- K8s manifests are raw YAML (no Kustomize) for maximum simplicity

## Relevant Paths
- Cloud storage: `src/aisec/core/cloud_storage.py`
- Falco agent: `src/aisec/agents/falco_runtime.py`
- Alert parser: `src/aisec/agents/falco_alert_parser.py`
- Falco rules: `src/aisec/agents/falco_rules.yaml`
- Config: `src/aisec/core/config.py` (5 new fields)
- Docker manager: `src/aisec/docker_/manager.py` (deploy_sidecar)
- Scan CLI: `src/aisec/cli/scan.py` (--cloud-storage flag)
- K8s manifests: `deploy/kubernetes/`
- Helm chart: `deploy/helm/aisec/`
- Docker Compose: `deploy/docker-compose.prod.yml`
- Tests: `tests/unit/test_cloud_storage.py`, `tests/unit/agents/test_falco_runtime_agent.py`, `tests/unit/test_falco_alert_parser.py`, `tests/unit/test_deploy_manifests.py`, `tests/unit/test_correlation_v17.py`

## Commands
- Run tests: `PYTHONPATH=src python3 -m pytest tests/ -x -q`
- Import check: `PYTHONPATH=src python3 -c "from aisec.agents.falco_runtime import FalcoRuntimeAgent; print('OK')"`
