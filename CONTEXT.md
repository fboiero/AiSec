# AiSec Session Context

## Current State
- **Version**: 1.9.0 (local, not yet committed)
- **Branch**: main
- **All tests**: 1,453 passed, 10 skipped

## What Was Completed in v1.9.0

### New Files (10)
1. `src/aisec/utils/url_validator.py` — SSRF protection for webhook URLs
2. `tests/unit/test_url_validator.py` — 12 tests
3. `tests/unit/test_error_responses.py` — 9 tests
4. `tests/unit/test_scan_persistence.py` — 15 tests
5. `tests/unit/test_webhook_persistence.py` — 11 tests
6. `tests/unit/test_scan_queue.py` — 5 tests
7. `tests/unit/test_security_headers.py` — 6 tests
8. `tests/unit/test_plugin_hooks.py` — 16 tests
9. `.github/workflows/codeql.yml` — Weekly + PR CodeQL analysis
10. `.github/dependabot.yml` — pip, GitHub Actions, Docker dependency updates

### Modified Files (14+)
1. `src/aisec/core/config.py` — Removed duplicate fields, added 5 new fields
2. `src/aisec/core/exceptions.py` — WebhookError, QueueFullError, ValidationError, error_response()
3. `src/aisec/core/history.py` — scan_reports + webhooks tables, 8 CRUD methods
4. `src/aisec/cli/serve.py` — Persistence, ThreadPoolExecutor, security headers, SSRF, cancel endpoint
5. `src/aisec/plugins/loader.py` — PluginManager class with error-isolated hooks
6. `src/aisec/agents/orchestrator.py` — Plugin hooks wired into scan lifecycle
7. `src/aisec/dashboard/context_processors.py` — Updated from _scan_store to _get_history()
8. `src/aisec/dashboard/views.py` — All _scan_store references to persistent store
9. `Dockerfile` — Multi-stage build, non-root user, HEALTHCHECK
10. `docker-compose.yml` — Resource limits, restart policy, named volume
11. `.github/workflows/ci.yml` — Bandit security lint step
12. `src/aisec/__init__.py` — Version 1.9.0
13. `pyproject.toml` — Version 1.9.0
14. `CHANGELOG.md` — v1.9.0 entry
15. `README.md` — Updated key features

## Pending
- Git commit, tag, push, and GitHub release for v1.9.0

## Key Decisions
- SQLite persistence for scan reports + webhooks (replaces in-memory dicts)
- ThreadPoolExecutor with configurable pool (default 4) instead of unbounded daemon threads
- Security headers injected in CorsMiddleware (CSP, X-Frame-Options, HSTS, etc.)
- SSRF protection via DNS resolution + private IP blocking
- PluginManager with error isolation — hook failures never crash scans
- Multi-stage Docker build with non-root user (UID 1000)
- CodeQL + Dependabot + Bandit for CI/CD security

## Known Issues
- `git status`/`git diff`/`git commit` can hang in this repo — workaround: use low-level git plumbing (write-tree, commit-tree, update-ref)

## Key Paths
- URL Validator: `src/aisec/utils/url_validator.py`
- Exceptions: `src/aisec/core/exceptions.py`
- History (persistence): `src/aisec/core/history.py`
- Serve API: `src/aisec/cli/serve.py`
- Plugin Manager: `src/aisec/plugins/loader.py`
- Orchestrator: `src/aisec/agents/orchestrator.py`
- Config: `src/aisec/core/config.py`

## Commands
- Run tests: `PYTHONPATH=src python3 -m pytest tests/unit/ -x -q`
- URL validator check: `PYTHONPATH=src python3 -c "from aisec.utils.url_validator import validate_webhook_url; print('OK')"`
- Plugin manager check: `PYTHONPATH=src python3 -c "from aisec.plugins.loader import PluginManager; print('OK')"`
