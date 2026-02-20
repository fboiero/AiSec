"""Network utilities for port scanning and HTTP probing."""

from __future__ import annotations

import logging
import socket
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def scan_common_ports(host: str, timeout: float = 1.0) -> list[int]:
    """Scan common ports on a host."""
    common_ports = [
        80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 5001,
        8000, 8001, 8888, 9000, 9090, 11434, 6333, 6334,
    ]
    open_ports = []
    for port in common_ports:
        if check_port(host, port, timeout):
            open_ports.append(port)
    return open_ports


async def probe_http(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Probe an HTTP endpoint and return response metadata."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            resp = await client.get(url)
            return {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content_length": len(resp.content),
                "server": resp.headers.get("server", ""),
                "has_cors": "access-control-allow-origin" in resp.headers,
            }
    except Exception as exc:
        return {"url": url, "error": str(exc)}


def check_tls(host: str, port: int = 443) -> dict[str, Any]:
    """Check TLS configuration of a host."""
    import ssl

    result: dict[str, Any] = {"host": host, "port": port}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()
                cert = ssock.getpeercert()
                if cert:
                    result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    result["expires"] = cert.get("notAfter", "")
                result["valid"] = True
    except ssl.SSLError as exc:
        result["valid"] = False
        result["error"] = str(exc)
    except Exception as exc:
        result["valid"] = False
        result["error"] = str(exc)
    return result
