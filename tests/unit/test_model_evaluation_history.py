from __future__ import annotations

from pathlib import Path

import pytest

from aisec.core.history import ScanHistory
from aisec.evaluation import ModelRiskEvaluationRequest, evaluate_model_risk


@pytest.fixture
def history(tmp_path: Path):
    db = ScanHistory(db_path=tmp_path / "history.db")
    yield db
    db.close()


def _request(request_id: str = "history-request") -> ModelRiskEvaluationRequest:
    return ModelRiskEvaluationRequest.model_validate(
        {
            "request_id": request_id,
            "source": "orchestai",
            "target": {
                "type": "rag_pipeline",
                "name": "History RAG",
                "provider": "openai",
                "model_id": "gpt-4.1",
                "capabilities": {"rag_enabled": True, "tools_enabled": True},
                "data_classes": ["pii"],
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
    )


class TestModelEvaluationHistory:
    def test_table_exists(self, history: ScanHistory) -> None:
        row = history._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='model_evaluations'"
        ).fetchone()

        assert row is not None

    def test_save_and_get_model_evaluation(self, history: ScanHistory) -> None:
        request = _request()
        result = evaluate_model_risk(request)

        evaluation_id = history.save_model_evaluation(request, result)
        stored = history.get_model_evaluation(evaluation_id)

        assert stored is not None
        assert stored["evaluation_id"] == result.evaluation_id
        assert stored["request_id"] == "history-request"
        assert stored["target_name"] == "History RAG"
        assert stored["result"]["schema_version"] == "aisec.model_risk.v1"
        assert stored["request"]["target"]["name"] == "History RAG"

    def test_list_and_count_model_evaluations(self, history: ScanHistory) -> None:
        first = _request("first")
        second = _request("second")
        history.save_model_evaluation(first, evaluate_model_risk(first))
        history.save_model_evaluation(second, evaluate_model_risk(second))

        rows = history.list_model_evaluations(limit=10)

        assert history.count_model_evaluations() == 2
        assert len(rows) == 2
        assert rows[0]["target_name"] == "History RAG"
        assert "result" not in rows[0]

    def test_list_model_evaluations_filters_by_target(self, history: ScanHistory) -> None:
        first = _request("first")
        second = _request("second")
        second.target.name = "Other RAG"
        history.save_model_evaluation(first, evaluate_model_risk(first))
        history.save_model_evaluation(second, evaluate_model_risk(second))

        rows = history.list_model_evaluations(target_name="Other RAG")

        assert history.count_model_evaluations(target_name="Other RAG") == 1
        assert len(rows) == 1
        assert rows[0]["target_name"] == "Other RAG"

    def test_model_evaluation_rollup(self, history: ScanHistory) -> None:
        first = _request("first")
        second = _request("second")
        second.target.name = "Other RAG"
        history.save_model_evaluation(first, evaluate_model_risk(first))
        history.save_model_evaluation(second, evaluate_model_risk(second))

        rollup = history.model_evaluation_rollup()
        filtered = history.model_evaluation_rollup(target_name="Other RAG")

        assert rollup["total_evaluations"] == 2
        assert rollup["unique_targets"] == 2
        assert rollup["average_risk_score"] > 0
        assert rollup["risk_counts"]
        assert rollup["policy_counts"]
        assert len(rollup["latest"]) == 2
        assert filtered["total_evaluations"] == 1
        assert filtered["unique_targets"] == 1

    def test_save_get_list_and_delete_model_baseline(self, history: ScanHistory) -> None:
        request = _request("baseline-source")
        result = evaluate_model_risk(request)
        evaluation_id = history.save_model_evaluation(request, result)

        baseline_id = history.save_model_baseline(
            "approved",
            "History RAG",
            evaluation_id,
            "Release approval baseline",
        )
        by_id = history.get_model_baseline(baseline_id=baseline_id)
        by_name = history.get_model_baseline(name="approved", target_name="History RAG")
        baselines = history.list_model_baselines(target_name="History RAG")

        assert by_id is not None
        assert by_id["name"] == "approved"
        assert by_name is not None
        assert by_name["baseline_id"] == baseline_id
        assert len(baselines) == 1
        assert history.delete_model_baseline(baseline_id) is True
        assert history.get_model_baseline(baseline_id=baseline_id) is None

    def test_save_list_and_delete_model_exception(self, history: ScanHistory) -> None:
        exception_id = history.save_model_exception(
            target_name="History RAG",
            finding_fingerprint="history rag|high|finding|gdpr",
            reason="Accepted for release window",
            accepted_by="security",
            expires_at="2026-06-01T00:00:00Z",
        )

        exceptions = history.list_model_exceptions(target_name="History RAG")
        fingerprints = history.accepted_model_exception_fingerprints("History RAG")

        assert len(exceptions) == 1
        assert exceptions[0]["exception_id"] == exception_id
        assert exceptions[0]["reason"] == "Accepted for release window"
        assert fingerprints == {"history rag|high|finding|gdpr"}
        assert history.delete_model_exception(exception_id) is True
        assert history.accepted_model_exception_fingerprints("History RAG") == set()

    def test_expired_model_exception_is_not_active(self, history: ScanHistory) -> None:
        exception_id = history.save_model_exception(
            target_name="History RAG",
            finding_fingerprint="history rag|high|expired|gdpr",
            reason="Expired acceptance",
            accepted_by="security",
            expires_at="2000-01-01T00:00:00Z",
        )

        assert history.list_model_exceptions(target_name="History RAG") == []
        assert history.accepted_model_exception_fingerprints("History RAG") == set()

        inactive_and_expired = history.list_model_exceptions(
            target_name="History RAG",
            active_only=False,
        )
        assert inactive_and_expired[0]["exception_id"] == exception_id
