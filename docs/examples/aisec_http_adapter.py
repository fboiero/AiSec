"""Reference HTTP adapter for optional AiSec model-risk evaluation.

This file is intentionally standalone so orchestrators can copy it without
importing AiSec internals. It calls an ``aisec serve`` instance and treats
network/server failures separately from AiSec policy results.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class AiSecHttpAdapterResult:
    """Outcome returned to the consuming orchestrator."""

    available: bool
    timed_out: bool
    result: dict[str, Any] | None = None
    status_code: int | None = None
    error: str = ""

    @property
    def succeeded(self) -> bool:
        """Whether AiSec produced a parseable evaluation result."""
        return self.result is not None


def evaluate_with_aisec_http(
    request: dict[str, Any],
    *,
    base_url: str = "http://127.0.0.1:8000",
    api_key: str | None = None,
    timeout_seconds: int = 30,
    headers: Mapping[str, str] | None = None,
) -> AiSecHttpAdapterResult:
    """POST a model-risk request to ``aisec serve`` and return a safe result.

    HTTP availability problems are adapter failures. A successful HTTP response
    can still contain ``policy_verdict.status == "fail"``; the consuming
    platform should decide whether to block, warn, or store evidence based on
    the parsed result.
    """
    url = f"{base_url.rstrip('/')}/api/evaluate/model/"
    body = json.dumps(request).encode("utf-8")
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **dict(headers or {}),
    }
    if api_key:
        request_headers["X-API-Key"] = api_key

    http_request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(http_request, timeout=timeout_seconds) as response:  # noqa: S310
            payload = response.read().decode("utf-8")
            return AiSecHttpAdapterResult(
                available=True,
                timed_out=False,
                status_code=response.status,
                result=json.loads(payload),
            )
    except TimeoutError:
        return AiSecHttpAdapterResult(
            available=True,
            timed_out=True,
            error=f"AiSec HTTP evaluation timed out after {timeout_seconds} seconds.",
        )
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        return AiSecHttpAdapterResult(
            available=True,
            timed_out=False,
            status_code=exc.code,
            error=payload or str(exc),
        )
    except urllib.error.URLError as exc:
        return AiSecHttpAdapterResult(
            available=False,
            timed_out=False,
            error=f"AiSec HTTP endpoint unavailable: {exc.reason}",
        )
    except json.JSONDecodeError as exc:
        return AiSecHttpAdapterResult(
            available=True,
            timed_out=False,
            error=f"AiSec HTTP response JSON could not be parsed: {exc}",
        )
