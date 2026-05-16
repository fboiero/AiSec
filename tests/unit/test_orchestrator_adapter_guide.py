from __future__ import annotations

from pathlib import Path


def test_orchestrator_adapter_guide_covers_integration_contract() -> None:
    guide = Path("docs/orchestrator-adapter-guide.md").read_text(encoding="utf-8")

    assert "schemas/model-risk-request.schema.json" in guide
    assert "schemas/model-risk-result.schema.json" in guide
    assert "ModelRiskEvaluationRequest" in guide
    assert "ModelRiskEvaluationResult" in guide
    assert "aisec evaluate model" in guide
    assert "POST /api/evaluate/model/" in guide
    assert "Exit code `1` with a valid result JSON" in guide
    assert "aisec evaluate summarize" in guide
    assert "aisec evaluate evidence" in guide
    assert "aisec evaluate compare" in guide
    assert "POST /api/evaluation-exceptions/" in guide


def test_documentation_index_links_orchestrator_adapter_guide() -> None:
    index = Path("docs/INDEX.md").read_text(encoding="utf-8")
    quickstart = Path("docs/quickstart.md").read_text(encoding="utf-8")
    protocol = Path("docs/orchestai-integration-protocol.md").read_text(encoding="utf-8")

    assert "orchestrator-adapter-guide.md" in index
    assert "orchestrator-adapter-guide.md" in quickstart
    assert "orchestrator-adapter-guide.md" in protocol
