from __future__ import annotations

import os
from pathlib import Path

import yaml


SCRIPT = Path("scripts/capture-managed-evidence.sh")


def test_managed_evidence_capture_script_collects_governance_endpoints() -> None:
    content = SCRIPT.read_text(encoding="utf-8")

    assert os.access(SCRIPT, os.X_OK)
    assert "AISEC_BASE_URL" in content
    assert "AISEC_EVIDENCE_DIR" in content
    assert "/api/live/" in content
    assert "/api/ready/" in content
    assert "/api/schema/" in content
    assert "/api/evaluations/rollup/" in content
    assert "/api/evaluations/" in content
    assert "/api/evaluation-baselines/" in content
    assert "/api/evaluation-exceptions/" in content
    assert "model-risk-rollup.json" in content
    assert "model-risk-baselines.json" in content
    assert "model-risk-exceptions.json" in content


def test_managed_deployment_docs_include_rollback_runbook_and_evidence_capture() -> None:
    managed = Path("docs/managed-deployment.md").read_text(encoding="utf-8")
    deploy_readme = Path("deploy/README.md").read_text(encoding="utf-8")

    assert "scripts/capture-managed-evidence.sh" in managed
    assert "## Rollback Runbook" in managed
    assert "kubectl -n aisec rollout undo deploy/aisec-api" in managed
    assert "helm rollback aisec <REVISION> -n aisec" in managed
    assert "failed-upgrade" in managed
    assert "post-rollback" in managed
    assert "scripts/capture-managed-evidence.sh" in deploy_readme


def test_docker_compose_image_tag_is_rollback_configurable() -> None:
    compose = yaml.safe_load(Path("deploy/docker-compose.prod.yml").read_text(encoding="utf-8"))

    assert compose["services"]["aisec-api"]["image"] == (
        "ghcr.io/fboiero/aisec:${AISEC_IMAGE_TAG:-1.10.0}"
    )
