from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
from io import BytesIO
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def _load_adapter() -> ModuleType:
    path = Path("docs/examples/aisec_http_adapter.py")
    spec = importlib.util.spec_from_file_location("aisec_http_adapter", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeHttpResponse:
    def __init__(self, payload: dict[str, object], status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def test_http_adapter_returns_model_risk_result() -> None:
    adapter = _load_adapter()
    payload = {
        "schema_version": "aisec.model_risk.v1",
        "request_id": "demo",
        "policy_verdict": {"status": "warn"},
    }

    with patch("urllib.request.urlopen", return_value=_FakeHttpResponse(payload)):
        result = adapter.evaluate_with_aisec_http({"target": {"name": "Demo"}})

    assert result.available is True
    assert result.timed_out is False
    assert result.succeeded is True
    assert result.status_code == 200
    assert result.result == payload


def test_http_adapter_reports_unavailable_endpoint() -> None:
    adapter = _load_adapter()

    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        result = adapter.evaluate_with_aisec_http({"target": {"name": "Demo"}})

    assert result.available is False
    assert result.timed_out is False
    assert result.succeeded is False
    assert "unavailable" in result.error


def test_http_adapter_reports_timeout() -> None:
    adapter = _load_adapter()

    with patch("urllib.request.urlopen", side_effect=TimeoutError):
        result = adapter.evaluate_with_aisec_http(
            {"target": {"name": "Demo"}},
            timeout_seconds=1,
        )

    assert result.available is True
    assert result.timed_out is True
    assert result.succeeded is False
    assert "timed out" in result.error


def test_http_adapter_reports_http_error_without_result() -> None:
    adapter = _load_adapter()
    error = urllib.error.HTTPError(
        url="http://127.0.0.1/api/evaluate/model/",
        code=400,
        msg="bad request",
        hdrs={},
        fp=BytesIO(b'{"error": {"code": "VALIDATION_ERROR"}}'),
    )

    with patch("urllib.request.urlopen", side_effect=error):
        result = adapter.evaluate_with_aisec_http({"target": {"name": "Demo"}})

    assert result.available is True
    assert result.timed_out is False
    assert result.succeeded is False
    assert result.status_code == 400
    assert "VALIDATION_ERROR" in result.error


def test_http_adapter_sets_api_key_header() -> None:
    adapter = _load_adapter()
    captured_headers = {}

    def fake_urlopen(request, **kwargs):  # noqa: ANN001, ANN202
        captured_headers.update(request.header_items())
        return _FakeHttpResponse({"ok": True})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        adapter.evaluate_with_aisec_http(
            {"target": {"name": "Demo"}},
            api_key="secret",
        )

    assert captured_headers["X-api-key"] == "secret"
