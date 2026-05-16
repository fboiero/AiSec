#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AISEC_BASE_URL:-http://localhost:8000}"
OUTPUT_DIR="${AISEC_EVIDENCE_DIR:-aisec-managed-evidence}"

mkdir -p "$OUTPUT_DIR"

echo "Capturing AiSec managed service evidence from $BASE_URL into $OUTPUT_DIR"

curl -fsS "$BASE_URL/api/live/" > "$OUTPUT_DIR/live.json"
curl -fsS "$BASE_URL/api/ready/" > "$OUTPUT_DIR/ready.json"
curl -fsS "$BASE_URL/api/schema/" > "$OUTPUT_DIR/openapi.json"
curl -fsS "$BASE_URL/api/evaluations/rollup/" > "$OUTPUT_DIR/model-risk-rollup.json"
curl -fsS "$BASE_URL/api/evaluations/" > "$OUTPUT_DIR/model-risk-evaluations.json"
curl -fsS "$BASE_URL/api/evaluation-baselines/" > "$OUTPUT_DIR/model-risk-baselines.json"
curl -fsS "$BASE_URL/api/evaluation-exceptions/" > "$OUTPUT_DIR/model-risk-exceptions.json"

cat > "$OUTPUT_DIR/README.md" <<EOF
# AiSec Managed Evidence Capture

- Base URL: \`$BASE_URL\`
- Captured at: \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`
- Files:
  - \`live.json\`
  - \`ready.json\`
  - \`openapi.json\`
  - \`model-risk-rollup.json\`
  - \`model-risk-evaluations.json\`
  - \`model-risk-baselines.json\`
  - \`model-risk-exceptions.json\`
EOF

echo "Evidence captured in $OUTPUT_DIR"
