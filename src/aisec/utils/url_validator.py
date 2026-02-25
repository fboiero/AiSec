"""URL validation utilities for SSRF protection."""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from aisec.core.exceptions import ValidationError

logger = logging.getLogger(__name__)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_webhook_url(url: str) -> str:
    """Validate a webhook URL is safe (no SSRF).

    Args:
        url: The URL to validate.

    Returns:
        The validated URL (normalized).

    Raises:
        ValidationError: If the URL targets a private/internal address
            or uses a blocked scheme.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            "url", f"Scheme '{parsed.scheme}' not allowed. Use http or https."
        )

    if not parsed.hostname:
        raise ValidationError("url", "URL must include a hostname.")

    # Resolve hostname to IP and check against private ranges
    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except OSError:
        raise ValidationError(
            "url", f"Cannot resolve hostname '{parsed.hostname}'."
        )

    for _family, _, _, _, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        for network in _PRIVATE_NETWORKS:
            if ip in network:
                raise ValidationError(
                    "url",
                    f"URL resolves to private/internal address ({ip}). "
                    "Webhook URLs must target public endpoints.",
                )

    logger.debug("Webhook URL validated: %s", url)
    return url
