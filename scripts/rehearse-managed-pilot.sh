#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AISEC_BASE_URL:-http://localhost:8000}"
RUN_ID="${AISEC_REHEARSAL_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
OUTPUT_ROOT="${AISEC_REHEARSAL_DIR:-aisec-managed-rehearsals}"
RUN_DIR="$OUTPUT_ROOT/$RUN_ID"

mkdir -p "$RUN_DIR"

echo "Starting AiSec managed pilot rehearsal"
echo "Base URL: $BASE_URL"
echo "Run directory: $RUN_DIR"

AISEC_BASE_URL="$BASE_URL" \
AISEC_EVIDENCE_DIR="$RUN_DIR/pre-smoke" \
  "$(dirname "$0")/capture-managed-evidence.sh"

AISEC_BASE_URL="$BASE_URL" \
  "$(dirname "$0")/smoke-managed-api.sh" \
  | tee "$RUN_DIR/smoke.log"

AISEC_BASE_URL="$BASE_URL" \
AISEC_EVIDENCE_DIR="$RUN_DIR/post-smoke" \
  "$(dirname "$0")/capture-managed-evidence.sh"

cat > "$RUN_DIR/README.md" <<EOF
# AiSec Managed Pilot Rehearsal

- Base URL: \`$BASE_URL\`
- Rehearsal ID: \`$RUN_ID\`
- Captured at: \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`
- Status: \`passed\`

## Artifacts

- \`pre-smoke/\`: evidence captured before the smoke evaluation.
- \`smoke.log\`: smoke test output.
- \`post-smoke/\`: evidence captured after the smoke evaluation.

## Expected Review

- Compare \`pre-smoke/model-risk-rollup.json\` and
  \`post-smoke/model-risk-rollup.json\`.
- Confirm the smoke evaluation appears in \`post-smoke/model-risk-evaluations.json\`.
- Attach this directory to the external pilot ticket or deployment report.
EOF

echo "AiSec managed pilot rehearsal passed: $RUN_DIR"
