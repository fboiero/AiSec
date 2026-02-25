"""Tests for SSRF protection in URL validator."""

from unittest.mock import patch

import pytest

from aisec.core.exceptions import ValidationError
from aisec.utils.url_validator import validate_webhook_url


def _mock_resolve(ip: str):
    """Return a mock getaddrinfo result for the given IP."""
    import socket

    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


class TestValidWebhookURLs:
    @patch("socket.getaddrinfo", return_value=_mock_resolve("93.184.216.34"))
    def test_valid_https_url(self, _mock):
        result = validate_webhook_url("https://example.com/webhook")
        assert result == "https://example.com/webhook"

    @patch("socket.getaddrinfo", return_value=_mock_resolve("93.184.216.34"))
    def test_valid_http_url(self, _mock):
        result = validate_webhook_url("http://example.com/webhook")
        assert result == "http://example.com/webhook"


class TestBlockedSchemes:
    def test_rejects_file_scheme(self):
        with pytest.raises(ValidationError, match="Scheme 'file' not allowed"):
            validate_webhook_url("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValidationError, match="Scheme 'ftp' not allowed"):
            validate_webhook_url("ftp://evil.com/data")

    def test_rejects_empty_scheme(self):
        with pytest.raises(ValidationError):
            validate_webhook_url("://no-scheme.com")

    def test_rejects_no_hostname(self):
        with pytest.raises(ValidationError, match="hostname"):
            validate_webhook_url("http:///path-only")


class TestPrivateIPBlocking:
    @patch("socket.getaddrinfo", return_value=_mock_resolve("127.0.0.1"))
    def test_rejects_localhost(self, _mock):
        with pytest.raises(ValidationError, match="private/internal"):
            validate_webhook_url("http://localhost/hook")

    @patch("socket.getaddrinfo", return_value=_mock_resolve("10.0.0.1"))
    def test_rejects_private_10x(self, _mock):
        with pytest.raises(ValidationError, match="private/internal"):
            validate_webhook_url("http://internal.corp/hook")

    @patch("socket.getaddrinfo", return_value=_mock_resolve("172.16.0.1"))
    def test_rejects_private_172x(self, _mock):
        with pytest.raises(ValidationError, match="private/internal"):
            validate_webhook_url("http://docker-host/hook")

    @patch("socket.getaddrinfo", return_value=_mock_resolve("192.168.1.1"))
    def test_rejects_private_192x(self, _mock):
        with pytest.raises(ValidationError, match="private/internal"):
            validate_webhook_url("http://router.local/hook")

    @patch("socket.getaddrinfo", return_value=[(10, 1, 0, "", ("::1", 0, 0, 0))])
    def test_rejects_ipv6_localhost(self, _mock):
        with pytest.raises(ValidationError, match="private/internal"):
            validate_webhook_url("http://[::1]/hook")


class TestDNSResolution:
    @patch("socket.getaddrinfo", side_effect=OSError("Name resolution failed"))
    def test_rejects_unresolvable(self, _mock):
        with pytest.raises(ValidationError, match="Cannot resolve"):
            validate_webhook_url("http://nonexistent.invalid/hook")
