from __future__ import annotations

import os
from pathlib import Path


SCRIPT = Path("scripts/smoke-managed-api.sh")


def test_managed_api_smoke_script_is_executable_and_checks_service_contract() -> None:
    content = SCRIPT.read_text(encoding="utf-8")

    assert os.access(SCRIPT, os.X_OK)
    assert "AISEC_BASE_URL" in content
    assert "AISEC_REQUEST_PATH" in content
    assert "/api/live/" in content
    assert "/api/ready/" in content
    assert "/api/evaluate/model/" in content
    assert "/api/evaluations/rollup/" in content
    assert "aisec.model_risk.v1" in content
    assert "policy_verdict" in content
    assert "total_evaluations" in content


def test_managed_deployment_docs_reference_smoke_script() -> None:
    managed = Path("docs/managed-deployment.md").read_text(encoding="utf-8")
    deploy_readme = Path("deploy/README.md").read_text(encoding="utf-8")

    assert "scripts/smoke-managed-api.sh" in managed
    assert "scripts/smoke-managed-api.sh" in deploy_readme
