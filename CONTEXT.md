# AiSec Session Context

## Current State
- **Version**: 1.8.0 (committed `2675882`, pushed to main)
- **Branch**: main
- **All tests**: 1,378 passed, 10 skipped

## What Was Completed in v1.8.0

### New Files (6)
1. `src/aisec/core/metrics.py` — Prometheus counters/gauges/histograms with no-op fallback
2. `src/aisec/core/scheduler.py` — APScheduler ScanScheduler with cron + aliases
3. `.dockerignore` — Excludes .git, tests, __pycache__, .github, docs, .claude, deploy
4. `tests/unit/test_metrics.py` — 11 tests
5. `tests/unit/test_scheduler.py` — 13 tests
6. `tests/unit/test_structured_logging.py` — 8 tests

### Modified Files (10)
1. `src/aisec/utils/logging.py` — Rewritten with structlog (JSON/console, bind_context)
2. `src/aisec/cli/serve.py` — /api/metrics/, /api/schedules/ endpoints, --schedule flags, request ID middleware
3. `src/aisec/cli/scan.py` — Scan/agent/finding metrics instrumentation
4. `src/aisec/core/config.py` — log_format, schedule_cron, schedule_image fields
5. `src/aisec/__init__.py` — Version 1.8.0
6. `pyproject.toml` — [metrics], [scheduler] extras in [all]
7. `CHANGELOG.md` — v1.8.0 entry
8. `README.md` — Observability, logging, scheduler sections + Layer 6 architecture
9. `DECISIONS.md` — v1.8.0 decision entry
10. `tests/unit/test_web_dashboard.py` — Version test updated

## Pending
- Nothing pending — v1.8.0 is released

## Key Decisions
- prometheus_client as optional [metrics] extra with no-op fallback
- APScheduler 3.x BackgroundScheduler (thread-based, matches Django sync model)
- structlog activated (was already in dependencies but unused)
- Request ID tracing via CorsMiddleware (no separate middleware)

## Known Issues
- `git status`/`git diff`/`git commit` can hang in this repo — workaround: use low-level git plumbing (write-tree, commit-tree, update-ref)

## Key Paths
- Metrics: `src/aisec/core/metrics.py`
- Scheduler: `src/aisec/core/scheduler.py`
- Logging: `src/aisec/utils/logging.py`
- Serve: `src/aisec/cli/serve.py`
- Config: `src/aisec/core/config.py`

## Commands
- Run tests: `PYTHONPATH=src python3 -m pytest tests/unit/ -x -q`
- Metrics check: `PYTHONPATH=src python3 -c "from aisec.core.metrics import get_metrics_text; print('OK')"`
- Scheduler check: `PYTHONPATH=src python3 -c "from aisec.core.scheduler import ScanScheduler; print('OK')"`
