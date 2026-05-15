from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def _load_adapter() -> ModuleType:
    path = Path("docs/examples/aisec_subprocess_adapter.py")
    spec = importlib.util.spec_from_file_location("aisec_subprocess_adapter", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_adapter_treats_missing_aisec_binary_as_optional_failure() -> None:
    adapter = _load_adapter()

    with patch("subprocess.run", side_effect=FileNotFoundError("aisec")):
        result = adapter.evaluate_with_aisec_cli({"target": {"name": "Demo"}})

    assert result.available is False
    assert result.timed_out is False
    assert result.succeeded is False
    assert "not found" in result.error


def test_adapter_treats_timeout_as_optional_failure() -> None:
    adapter = _load_adapter()

    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["aisec"], timeout=1),
    ):
        result = adapter.evaluate_with_aisec_cli(
            {"target": {"name": "Demo"}},
            timeout_seconds=1,
        )

    assert result.available is True
    assert result.timed_out is True
    assert result.succeeded is False
    assert "timed out" in result.error


def test_adapter_returns_result_when_policy_gate_exits_nonzero() -> None:
    adapter = _load_adapter()
    payload = {
        "schema_version": "aisec.model_risk.v1",
        "request_id": "demo",
        "policy_verdict": {"status": "fail"},
    }

    def fake_run(args, **kwargs):  # noqa: ANN001, ANN202
        output_path = Path(args[args.index("--output") + 1])
        output_path.write_text(
            adapter.json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args=args, returncode=1, stderr="", stdout="")

    with patch("subprocess.run", side_effect=fake_run):
        result = adapter.evaluate_with_aisec_cli({"target": {"name": "Demo"}})

    assert result.available is True
    assert result.timed_out is False
    assert result.succeeded is True
    assert result.result == payload


def test_adapter_reports_cli_failure_without_result_json() -> None:
    adapter = _load_adapter()

    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["aisec"],
            returncode=2,
            stderr="invalid request",
            stdout="",
        ),
    ):
        result = adapter.evaluate_with_aisec_cli({"target": {"name": "Demo"}})

    assert result.available is True
    assert result.timed_out is False
    assert result.succeeded is False
    assert result.error == "invalid request"
