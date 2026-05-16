from __future__ import annotations

import pytest


def test_model_risk_api_url_names_resolve() -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.config import _configure_django

    _configure_django()

    from django.urls import reverse

    assert reverse("evaluate-model-risk") == "/api/evaluate/model/"
    assert reverse("list-model-risk-evaluations") == "/api/evaluations/"
    assert reverse("model-risk-evaluation-rollup") == "/api/evaluations/rollup/"
    assert (
        reverse("get-model-risk-evaluation", kwargs={"evaluation_id": "eval-1"})
        == "/api/evaluations/eval-1/"
    )
    assert reverse("model-risk-baselines") == "/api/evaluation-baselines/"
    assert reverse("model-risk-exceptions") == "/api/evaluation-exceptions/"
    assert (
        reverse("model-risk-baseline-detail", kwargs={"baseline_id": "base-1"})
        == "/api/evaluation-baselines/base-1/"
    )
    assert (
        reverse("delete-model-risk-exception", kwargs={"exception_id": "exc-1"})
        == "/api/evaluation-exceptions/exc-1/"
    )
    assert (
        reverse("compare-model-risk-baseline", kwargs={"baseline_id": "base-1"})
        == "/api/evaluation-baselines/base-1/compare/"
    )


def test_schema_views_configure_django_before_importing_drf() -> None:
    pytest.importorskip("rest_framework")

    from aisec.api.schema import _get_schema_views

    views = _get_schema_views()

    assert callable(views["schema_json"])
    assert callable(views["swagger_ui"])
