from __future__ import annotations

import os
from pathlib import Path


SCRIPT = Path("scripts/rehearse-managed-pilot.sh")


def test_managed_pilot_rehearsal_script_orchestrates_capture_and_smoke() -> None:
    content = SCRIPT.read_text(encoding="utf-8")

    assert os.access(SCRIPT, os.X_OK)
    assert "AISEC_BASE_URL" in content
    assert "AISEC_REHEARSAL_ID" in content
    assert "AISEC_REHEARSAL_DIR" in content
    assert "capture-managed-evidence.sh" in content
    assert "smoke-managed-api.sh" in content
    assert "pre-smoke" in content
    assert "post-smoke" in content
    assert "smoke.log" in content
    assert "model-risk-rollup.json" in content
    assert "model-risk-evaluations.json" in content


def test_managed_deployment_docs_reference_pilot_rehearsal() -> None:
    managed = Path("docs/managed-deployment.md").read_text(encoding="utf-8")
    product = Path("docs/product-strategy-2026.md").read_text(encoding="utf-8")

    assert "scripts/rehearse-managed-pilot.sh" in managed
    assert "managed pilot rehearsal" in managed.lower()
    assert "managed pilot rehearsal" in product.lower()
