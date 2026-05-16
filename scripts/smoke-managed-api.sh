#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${AISEC_BASE_URL:-http://localhost:8000}"
REQUEST_PATH="${AISEC_REQUEST_PATH:-docs/examples/orchestai-usecase-customer-support-rag.json}"
TMP_DIR="${TMPDIR:-/tmp}/aisec-managed-smoke"
RESULT_PATH="$TMP_DIR/model-risk-result.json"
ROLLUP_PATH="$TMP_DIR/model-risk-rollup.json"

mkdir -p "$TMP_DIR"

echo "Checking AiSec liveness at $BASE_URL/api/live/"
curl -fsS "$BASE_URL/api/live/" >/dev/null

echo "Checking AiSec readiness at $BASE_URL/api/ready/"
curl -fsS "$BASE_URL/api/ready/" >/dev/null

echo "Submitting model-risk evaluation from $REQUEST_PATH"
curl -fsS \
  -H 'Content-Type: application/json' \
  --data @"$REQUEST_PATH" \
  "$BASE_URL/api/evaluate/model/" \
  > "$RESULT_PATH"

echo "Fetching model-risk rollup"
curl -fsS "$BASE_URL/api/evaluations/rollup/" > "$ROLLUP_PATH"

python - "$RESULT_PATH" "$ROLLUP_PATH" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rollup = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

if result.get("schema_version") != "aisec.model_risk.v1":
    raise SystemExit("Unexpected schema_version in evaluation result")
if not result.get("evaluation_id"):
    raise SystemExit("Missing evaluation_id in evaluation result")
if "policy_verdict" not in result:
    raise SystemExit("Missing policy_verdict in evaluation result")
if rollup.get("total_evaluations", 0) < 1:
    raise SystemExit("Rollup did not include the submitted evaluation")

print(
    "AiSec managed API smoke passed: "
    f"evaluation_id={result['evaluation_id']} "
    f"risk={result.get('overall_risk')} "
    f"verdict={result['policy_verdict'].get('status')}"
)
PY
