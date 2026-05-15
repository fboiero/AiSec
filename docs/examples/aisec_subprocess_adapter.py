"""Reference subprocess adapter for optional AiSec model-risk evaluation.

This file is intentionally standalone so orchestrators can copy it without
importing AiSec internals. It treats missing AiSec binaries and timeouts as
adapter failures, while policy failures still return the parsed AiSec result.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


@dataclass(frozen=True)
class AiSecAdapterResult:
    """Outcome returned to the consuming orchestrator."""

    available: bool
    timed_out: bool
    result: dict[str, Any] | None = None
    error: str = ""

    @property
    def succeeded(self) -> bool:
        """Whether AiSec produced a parseable evaluation result."""
        return self.result is not None


def evaluate_with_aisec_cli(
    request: dict[str, Any],
    *,
    aisec_command: str | Sequence[str] = "aisec",
    fail_on: str = "critical",
    timeout_seconds: int = 600,
    work_dir: str | Path | None = None,
) -> AiSecAdapterResult:
    """Run ``aisec evaluate model`` and return a platform-safe adapter result.

    ``policy_verdict.status == "fail"`` makes the AiSec CLI exit with code 1.
    That is still a successful evaluator invocation when the result JSON exists;
    the consuming platform should decide whether to block, warn, or store
    evidence based on the parsed policy verdict.
    """
    command = [aisec_command] if isinstance(aisec_command, str) else list(aisec_command)
    if not command:
        return AiSecAdapterResult(
            available=False,
            timed_out=False,
            error="AiSec command is empty.",
        )

    with tempfile.TemporaryDirectory(prefix="aisec-eval-", dir=work_dir) as tmp:
        tmp_path = Path(tmp)
        request_path = tmp_path / "request.json"
        result_path = tmp_path / "result.json"
        request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")

        args = [
            *command,
            "evaluate",
            "model",
            "--input",
            str(request_path),
            "--output",
            str(result_path),
            "--fail-on",
            fail_on,
            "--quiet",
        ]

        try:
            completed = subprocess.run(  # noqa: S603
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            return AiSecAdapterResult(
                available=False,
                timed_out=False,
                error=f"AiSec binary not found: {exc}",
            )
        except subprocess.TimeoutExpired:
            return AiSecAdapterResult(
                available=True,
                timed_out=True,
                error=f"AiSec evaluation timed out after {timeout_seconds} seconds.",
            )

        if result_path.exists():
            try:
                return AiSecAdapterResult(
                    available=True,
                    timed_out=False,
                    result=json.loads(result_path.read_text(encoding="utf-8")),
                )
            except json.JSONDecodeError as exc:
                return AiSecAdapterResult(
                    available=True,
                    timed_out=False,
                    error=f"AiSec result JSON could not be parsed: {exc}",
                )

        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        message = stderr or stdout or f"AiSec exited with code {completed.returncode}."
        return AiSecAdapterResult(available=True, timed_out=False, error=message)
