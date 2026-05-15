"""In-memory per-IP rate limiting for the AiSec REST API."""

from __future__ import annotations

import collections
import os
import threading
import time
from typing import Any


# Shared state for the throttle -- {ip: deque_of_timestamps}
_rate_limit_cache: dict[str, collections.deque] = {}
_rate_limit_lock = threading.Lock()


def _parse_rate_limit(value: str) -> tuple[int, int]:
    """Parse a rate-limit string like '100/min' into (num_requests, window_seconds)."""
    units = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600}
    try:
        num_str, unit = value.strip().split("/")
        num = int(num_str)
        window = units.get(unit.strip(), 60)
        return num, window
    except (ValueError, KeyError):
        return 100, 60  # default: 100/min


class SimpleRateThrottle:
    """In-memory per-IP rate limiting.

    Default: 100 requests per minute, configurable via the
    ``AISEC_RATE_LIMIT`` environment variable (e.g. ``"200/min"``,
    ``"10/s"``).
    """

    def __init__(self) -> None:
        raw = os.environ.get("AISEC_RATE_LIMIT", "100/min")
        self.num_requests, self.window = _parse_rate_limit(raw)

    def allow_request(self, request: Any, view: Any) -> bool:
        """Return *True* if the request should be allowed."""
        ip = self._get_client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window

        with _rate_limit_lock:
            if ip not in _rate_limit_cache:
                _rate_limit_cache[ip] = collections.deque()

            history = _rate_limit_cache[ip]

            while history and history[0] < cutoff:
                history.popleft()

            if len(history) >= self.num_requests:
                return False

            history.append(now)
            return True

    def wait(self) -> float | None:
        """Seconds to wait before the next request is allowed (optional)."""
        return None

    def get_remaining(self, request: Any) -> tuple[int, int]:
        """Return (limit, remaining) for the given request IP."""
        ip = self._get_client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window

        with _rate_limit_lock:
            history = _rate_limit_cache.get(ip, collections.deque())
            active = sum(1 for t in history if t >= cutoff)

        remaining = max(0, self.num_requests - active)
        return self.num_requests, remaining

    @staticmethod
    def _get_client_ip(request: Any) -> str:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


# Singleton throttle instance
_throttle_instance: SimpleRateThrottle | None = None


def _get_throttle() -> SimpleRateThrottle:
    global _throttle_instance
    if _throttle_instance is None:
        _throttle_instance = SimpleRateThrottle()
    return _throttle_instance
