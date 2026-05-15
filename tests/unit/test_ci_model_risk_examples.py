from __future__ import annotations

from pathlib import Path


EXAMPLES_DIR = Path("docs/examples")


def test_github_actions_model_risk_example_uses_evaluator_and_artifact() -> None:
    content = (EXAMPLES_DIR / "github-actions-model-risk.yml").read_text(encoding="utf-8")

    assert "aisec evaluate model" in content
    assert "--input \"$AISEC_REQUEST\"" in content
    assert "--output \"$AISEC_RESULT\"" in content
    assert "--fail-on \"$AISEC_FAIL_ON\"" in content
    assert "actions/upload-artifact@v4" in content
    assert "aisec-results/model-risk-result.json" in content


def test_gitlab_model_risk_example_uses_evaluator_and_artifact() -> None:
    content = (EXAMPLES_DIR / "gitlab-model-risk.yml").read_text(encoding="utf-8")

    assert "aisec evaluate model" in content
    assert "--input \"$AISEC_REQUEST\"" in content
    assert "--output \"$AISEC_RESULT\"" in content
    assert "--fail-on \"$AISEC_FAIL_ON\"" in content
    assert "artifacts:" in content
    assert "aisec-results/model-risk-result.json" in content


def test_ci_model_risk_examples_reference_existing_request() -> None:
    request_path = EXAMPLES_DIR / "orchestai-model-risk-request.json"
    assert request_path.exists()

    for filename in ["github-actions-model-risk.yml", "gitlab-model-risk.yml"]:
        content = (EXAMPLES_DIR / filename).read_text(encoding="utf-8")
        assert str(request_path) in content
