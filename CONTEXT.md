# AiSec Session Context

## Current Goal
v1.6.0 is **implemented and tested** (pending commit/push/release).

## Plan
v1.6.0 — Web UI Dashboard (delivered, 17 new files, 5 modified, 28 tests).

## Completed
- **Dashboard package** (`src/aisec/dashboard/`) with views, urls, templates, context processors
- **11 Django templates**: base.html (dark theme, sidebar nav, inline CSS), home (charts, cards), scans (paginated/filterable), scan_detail (tabbed Alpine.js), findings (HTMX-powered explorer), trends (Chart.js time-series), policies (built-in + saved), new_scan (form), 3 HTMX partials (scan_status, scan_table, finding_rows)
- **10 view functions** in views.py (~280 lines): home, scan_list, scan_detail, findings_explorer, trends, policies, new_scan, partial_scan_table, partial_scan_status, partial_finding_rows
- **5 new ScanHistory methods**: severity_distribution(), search_findings(), global_trend(), distinct_targets(), count_scans()
- **serve.py** updated: --dashboard/--no-dashboard flag, TEMPLATES config, CSRF middleware, dashboard URL include, save_scan in _run_scan_in_thread
- **CDN libraries**: Chart.js 4.x (charts), Alpine.js 3.x (reactivity), HTMX 1.9.x (partial updates)
- **Version** bumped to 1.6.0 in pyproject.toml and __init__.py
- **CHANGELOG.md** updated with v1.6.0 entry
- **README.md** updated (Web UI Dashboard section, feature list, roadmap checkbox)
- **test_web_dashboard.py** — 28 tests (18 pass, 10 skip when Django absent)

## Pending
- Git commit and push
- GitHub release

## Key Decisions
- Dashboard served at /dashboard/ via Django templates (not SPA/React) — no new build tooling
- CDN-loaded JS libraries (Chart.js, Alpine.js, HTMX) — no npm/node dependencies
- Inline CSS in base.html reusing styles.css variables — consistent with report pattern
- HTMX polling every 2s for scan status — no SSE/WebSocket needed
- All templates use custom CSS classes from base.html (not Bootstrap/Tailwind)
- --dashboard flag defaults to enabled for immediate usability
- save_scan() call added to _run_scan_in_thread to persist API scans to SQLite

## Relevant Paths
- Dashboard: `src/aisec/dashboard/{__init__,views,urls,context_processors}.py`
- Templates: `src/aisec/dashboard/templates/dashboard/{base,home,scans,scan_detail,findings,trends,policies,new_scan}.html`
- Partials: `src/aisec/dashboard/templates/dashboard/partials/{scan_status,scan_table,finding_rows}.html`
- History: `src/aisec/core/history.py` (5 new methods)
- Serve: `src/aisec/cli/serve.py` (--dashboard, save_scan, URL routing)
- Tests: `tests/unit/test_web_dashboard.py`

## Commands
- Run tests: `PYTHONPATH=src python3 -m pytest tests/ -x -q`
- Run dashboard tests: `PYTHONPATH=src python3 -m pytest tests/unit/test_web_dashboard.py -x -q`
- Import check: `PYTHONPATH=src python3 -c "from aisec.dashboard.views import home; print('OK')"`
