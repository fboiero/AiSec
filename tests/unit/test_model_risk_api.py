from __future__ import annotations

import pytest


def _payload() -> dict[str, object]:
    return {
        "request_id": "api-test-request",
        "source": "orchestai",
        "target": {
            "type": "rag_pipeline",
            "name": "API Customer RAG",
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


def test_model_risk_api_endpoint_returns_evaluation_result(monkeypatch, tmp_path) -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.views import _get_views
    from aisec.core.history import ScanHistory
    import aisec.api.scan_runner as scan_runner

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-history.db"))

    _configure_django()
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    request = factory.post("/api/evaluate/model/", _payload(), format="json")

    response = _get_views()["evaluate_model_risk"](request)

    assert response.status_code == 200
    assert response.data["schema_version"] == "aisec.model_risk.v1"
    assert response.data["request_id"] == "api-test-request"
    assert response.data["target"]["name"] == "API Customer RAG"
    assert response.data["policy_verdict"]["status"] in {"pass", "warn", "fail"}


def test_model_risk_api_endpoint_persists_evaluation(monkeypatch, tmp_path) -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.scan_runner import _get_history
    from aisec.api.views import _get_views
    from aisec.core.history import ScanHistory
    import aisec.api.scan_runner as scan_runner

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-history.db"))

    _configure_django()
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    request = factory.post("/api/evaluate/model/", _payload(), format="json")

    response = _get_views()["evaluate_model_risk"](request)

    assert response.status_code == 200
    stored = _get_history().get_model_evaluation(response.data["evaluation_id"])
    assert stored is not None
    assert stored["request_id"] == "api-test-request"
    assert stored["result"]["target"]["name"] == "API Customer RAG"


def test_model_risk_api_lists_and_gets_persisted_evaluations(monkeypatch, tmp_path) -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.views import _get_views
    from aisec.core.history import ScanHistory
    import aisec.api.scan_runner as scan_runner

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-history.db"))

    _configure_django()
    from rest_framework.test import APIRequestFactory

    views = _get_views()
    factory = APIRequestFactory()
    create_request = factory.post("/api/evaluate/model/", _payload(), format="json")
    create_response = views["evaluate_model_risk"](create_request)
    evaluation_id = create_response.data["evaluation_id"]

    list_request = factory.get("/api/evaluations/")
    list_response = views["list_model_risk_evaluations"](list_request)
    detail_request = factory.get(f"/api/evaluations/{evaluation_id}/")
    detail_response = views["get_model_risk_evaluation"](detail_request, evaluation_id)

    assert list_response.status_code == 200
    assert list_response.data["total"] == 1
    assert list_response.data["results"][0]["evaluation_id"] == evaluation_id
    assert detail_response.status_code == 200
    assert detail_response.data["evaluation_id"] == evaluation_id
    assert detail_response.data["result"]["schema_version"] == "aisec.model_risk.v1"


def test_model_risk_api_returns_evaluation_rollup(monkeypatch, tmp_path) -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.views import _get_views
    from aisec.core.history import ScanHistory
    import aisec.api.scan_runner as scan_runner

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-history.db"))

    _configure_django()
    from rest_framework.test import APIRequestFactory

    views = _get_views()
    factory = APIRequestFactory()
    views["evaluate_model_risk"](
        factory.post("/api/evaluate/model/", _payload(), format="json")
    )

    response = views["model_risk_evaluation_rollup"](factory.get("/api/evaluations/rollup/"))

    assert response.status_code == 200
    assert response.data["total_evaluations"] == 1
    assert response.data["unique_targets"] == 1
    assert response.data["average_risk_score"] > 0
    assert response.data["risk_counts"]
    assert response.data["policy_counts"]
    assert response.data["latest"][0]["target_name"] == "API Customer RAG"


def test_model_risk_api_creates_lists_and_compares_baselines(monkeypatch, tmp_path) -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.views import _get_views
    from aisec.core.history import ScanHistory
    import aisec.api.scan_runner as scan_runner

    monkeypatch.setattr(scan_runner, "_history", ScanHistory(tmp_path / "api-history.db"))

    _configure_django()
    from rest_framework.test import APIRequestFactory

    views = _get_views()
    factory = APIRequestFactory()
    first = views["evaluate_model_risk"](
        factory.post("/api/evaluate/model/", _payload(), format="json")
    )
    second_payload = _payload()
    second_payload["request_id"] = "api-test-request-2"
    second = views["evaluate_model_risk"](
        factory.post("/api/evaluate/model/", second_payload, format="json")
    )

    create_baseline = views["model_risk_baselines"](
        factory.post(
            "/api/evaluation-baselines/",
            {
                "name": "approved",
                "target_name": "API Customer RAG",
                "evaluation_id": first.data["evaluation_id"],
                "description": "approved baseline",
            },
            format="json",
        )
    )
    baseline_id = create_baseline.data["baseline_id"]
    list_baselines = views["model_risk_baselines"](factory.get("/api/evaluation-baselines/"))
    detail = views["model_risk_baseline_detail"](
        factory.get(f"/api/evaluation-baselines/{baseline_id}/"),
        baseline_id,
    )
    comparison = views["compare_model_risk_baseline"](
        factory.post(
            f"/api/evaluation-baselines/{baseline_id}/compare/",
            {"current_evaluation_id": second.data["evaluation_id"]},
            format="json",
        ),
        baseline_id,
    )

    assert create_baseline.status_code == 201
    assert list_baselines.status_code == 200
    assert list_baselines.data[0]["baseline_id"] == baseline_id
    assert detail.status_code == 200
    assert detail.data["name"] == "approved"
    assert comparison.status_code == 200
    assert comparison.data["baseline_request_id"] == "api-test-request"
    assert comparison.data["current_request_id"] == "api-test-request-2"


def test_model_risk_api_endpoint_reports_validation_errors() -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django
    from aisec.api.views import _get_views

    _configure_django()
    from rest_framework.test import APIRequestFactory

    factory = APIRequestFactory()
    request = factory.post(
        "/api/evaluate/model/",
        {"target": "not-an-object"},
        format="json",
    )

    response = _get_views()["evaluate_model_risk"](request)

    assert response.status_code == 400
