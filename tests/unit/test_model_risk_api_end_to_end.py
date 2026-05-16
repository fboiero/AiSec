from __future__ import annotations

import pytest


def _payload(request_id: str = "api-e2e-request") -> dict[str, object]:
    return {
        "request_id": request_id,
        "source": "orchestai",
        "target": {
            "type": "rag_pipeline",
            "name": "E2E Customer RAG",
            "provider": "openai",
            "model_id": "gpt-4.1",
            "capabilities": {
                "rag_enabled": True,
                "tools_enabled": True,
            },
            "data_classes": ["pii", "customer_messages"],
        },
        "frameworks": ["owasp_llm", "owasp_agentic", "gdpr"],
        "context": {
            "safeguards": {
                "pii_redaction": False,
                "prompt_logging_disabled": False,
                "retrieval_filtering": False,
                "tool_approval_required": False,
            }
        },
        "policy": {"fail_on": "none"},
    }


def _client(monkeypatch, tmp_path):  # noqa: ANN001, ANN202
    pytest.importorskip("rest_framework")

    import aisec.api.scan_runner as scan_runner
    from aisec.api.config import _configure_django
    from aisec.core.history import ScanHistory

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-e2e.db"))
    _configure_django()

    from rest_framework.test import APIClient

    return APIClient()


def test_model_risk_api_end_to_end_evaluate_history_rollup(monkeypatch, tmp_path) -> None:
    client = _client(monkeypatch, tmp_path)

    evaluate = client.post("/api/evaluate/model/", _payload(), format="json")
    evaluation_id = evaluate.json()["evaluation_id"]
    listing = client.get("/api/evaluations/")
    detail = client.get(f"/api/evaluations/{evaluation_id}/")
    rollup = client.get("/api/evaluations/rollup/")

    assert evaluate.status_code == 200
    assert evaluate.json()["schema_version"] == "aisec.model_risk.v1"
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["results"][0]["evaluation_id"] == evaluation_id
    assert detail.status_code == 200
    assert detail.json()["result"]["target"]["name"] == "E2E Customer RAG"
    assert rollup.status_code == 200
    assert rollup.json()["total_evaluations"] == 1
    assert rollup.json()["latest"][0]["evaluation_id"] == evaluation_id


def test_model_risk_api_end_to_end_baseline_compare_delete(monkeypatch, tmp_path) -> None:
    client = _client(monkeypatch, tmp_path)

    first = client.post("/api/evaluate/model/", _payload("baseline"), format="json")
    current = client.post("/api/evaluate/model/", _payload("current"), format="json")
    baseline = client.post(
        "/api/evaluation-baselines/",
        {
            "name": "approved",
            "target_name": "E2E Customer RAG",
            "evaluation_id": first.json()["evaluation_id"],
            "description": "approved release",
        },
        format="json",
    )
    baseline_id = baseline.json()["baseline_id"]
    comparison = client.post(
        f"/api/evaluation-baselines/{baseline_id}/compare/",
        {"current_evaluation_id": current.json()["evaluation_id"]},
        format="json",
    )
    deleted = client.delete(f"/api/evaluation-baselines/{baseline_id}/")
    missing = client.get(f"/api/evaluation-baselines/{baseline_id}/")

    assert baseline.status_code == 201
    assert comparison.status_code == 200
    assert comparison.json()["baseline_request_id"] == "baseline"
    assert comparison.json()["current_request_id"] == "current"
    assert deleted.status_code == 200
    assert missing.status_code == 404


def test_model_risk_api_end_to_end_negative_paths(monkeypatch, tmp_path) -> None:
    client = _client(monkeypatch, tmp_path)

    missing_evaluation = client.get("/api/evaluations/missing-eval/")
    invalid_baseline_body = client.post(
        "/api/evaluation-baselines/",
        {"name": "approved"},
        format="json",
    )
    missing_baseline_source = client.post(
        "/api/evaluation-baselines/",
        {
            "name": "approved",
            "target_name": "E2E Customer RAG",
            "evaluation_id": "missing-eval",
        },
        format="json",
    )
    missing_baseline = client.get("/api/evaluation-baselines/missing-base/")
    missing_compare_baseline = client.post(
        "/api/evaluation-baselines/missing-base/compare/",
        {"current_evaluation_id": "missing-eval"},
        format="json",
    )

    first = client.post("/api/evaluate/model/", _payload("baseline"), format="json")
    baseline = client.post(
        "/api/evaluation-baselines/",
        {
            "name": "approved",
            "target_name": "E2E Customer RAG",
            "evaluation_id": first.json()["evaluation_id"],
        },
        format="json",
    )
    missing_current = client.post(
        f"/api/evaluation-baselines/{baseline.json()['baseline_id']}/compare/",
        {"current_evaluation_id": "missing-current"},
        format="json",
    )
    invalid_compare_body = client.post(
        f"/api/evaluation-baselines/{baseline.json()['baseline_id']}/compare/",
        {},
        format="json",
    )

    assert missing_evaluation.status_code == 404
    assert missing_evaluation.json()["error"]["code"] == "EVALUATION_NOT_FOUND"
    assert invalid_baseline_body.status_code == 400
    assert "evaluation_id" in invalid_baseline_body.json()
    assert missing_baseline_source.status_code == 404
    assert missing_baseline_source.json()["error"]["code"] == "EVALUATION_NOT_FOUND"
    assert missing_baseline.status_code == 404
    assert missing_baseline.json()["error"]["code"] == "BASELINE_NOT_FOUND"
    assert missing_compare_baseline.status_code == 404
    assert missing_compare_baseline.json()["error"]["code"] == "BASELINE_NOT_FOUND"
    assert missing_current.status_code == 404
    assert missing_current.json()["error"]["code"] == "EVALUATION_NOT_FOUND"
    assert invalid_compare_body.status_code == 400
    assert "current_evaluation_id" in invalid_compare_body.json()


def test_model_risk_api_end_to_end_exceptions_accept_new_findings(monkeypatch, tmp_path) -> None:
    client = _client(monkeypatch, tmp_path)

    clean = _payload("baseline-clean")
    clean["target"]["capabilities"]["tools_enabled"] = False  # type: ignore[index]
    clean["context"]["safeguards"].update(  # type: ignore[index,union-attr]
        {
            "pii_redaction": True,
            "prompt_logging_disabled": True,
            "consent_required": True,
            "retention_policy_defined": True,
            "retrieval_filtering": True,
            "tenant_isolation": True,
            "output_filtering": True,
            "audit_logging": True,
            "rate_limiting": True,
        }
    )
    baseline_eval = client.post("/api/evaluate/model/", clean, format="json")
    current_eval = client.post("/api/evaluate/model/", _payload("current-risk"), format="json")
    baseline = client.post(
        "/api/evaluation-baselines/",
        {
            "name": "approved-clean",
            "target_name": "E2E Customer RAG",
            "evaluation_id": baseline_eval.json()["evaluation_id"],
        },
        format="json",
    )
    baseline_id = baseline.json()["baseline_id"]
    first_compare = client.post(
        f"/api/evaluation-baselines/{baseline_id}/compare/",
        {"current_evaluation_id": current_eval.json()["evaluation_id"]},
        format="json",
    )
    fingerprints = [finding["fingerprint"] for finding in first_compare.json()["new_findings"]]
    exceptions_created = [
        client.post(
            "/api/evaluation-exceptions/",
            {
                "target_name": "E2E Customer RAG",
                "finding_fingerprint": fingerprint,
                "reason": "Accepted for pilot window",
                "accepted_by": "security",
            },
            format="json",
        )
        for fingerprint in fingerprints
    ]
    exceptions = client.get("/api/evaluation-exceptions/?target_name=E2E Customer RAG")
    second_compare = client.post(
        f"/api/evaluation-baselines/{baseline_id}/compare/",
        {"current_evaluation_id": current_eval.json()["evaluation_id"]},
        format="json",
    )
    deleted = client.delete(
        f"/api/evaluation-exceptions/{exceptions_created[0].json()['exception_id']}/"
    )

    assert first_compare.status_code == 200
    assert first_compare.json()["has_regression"] is True
    assert all(response.status_code == 201 for response in exceptions_created)
    assert exceptions.status_code == 200
    assert {row["finding_fingerprint"] for row in exceptions.json()} == set(fingerprints)
    assert second_compare.status_code == 200
    assert {
        finding["fingerprint"]
        for finding in second_compare.json()["accepted_new_findings"]
    } == set(fingerprints)
    assert second_compare.json()["unaccepted_new_findings"] == []
    assert second_compare.json()["has_regression"] is False
    assert deleted.status_code == 200
