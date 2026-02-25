"""Tests for security headers in CorsMiddleware."""

import os
from unittest.mock import MagicMock, patch


class TestSecurityHeaders:
    def _make_middleware_call(self, env_vars=None):
        """Helper to invoke CorsMiddleware and return the response."""
        from aisec.cli.serve import CorsMiddleware

        mock_response = MagicMock()
        mock_response.__setitem__ = MagicMock()
        mock_response.__getitem__ = MagicMock(return_value="")
        mock_response.status_code = 200

        mock_get_response = MagicMock(return_value=mock_response)
        middleware = CorsMiddleware(mock_get_response)

        mock_request = MagicMock()
        mock_request.META = {"REMOTE_ADDR": "127.0.0.1"}
        mock_request.method = "GET"
        mock_request.path = "/api/health/"
        mock_request.is_secure.return_value = False

        env = {"AISEC_SECURITY_HEADERS": "true"}
        if env_vars:
            env.update(env_vars)

        with patch.dict(os.environ, env, clear=False):
            result = middleware(mock_request)

        return result, mock_response

    def test_security_headers_present_by_default(self):
        _, response = self._make_middleware_call()
        set_headers = {
            call.args[0]: call.args[1]
            for call in response.__setitem__.call_args_list
        }
        assert "X-Content-Type-Options" in set_headers
        assert set_headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in set_headers
        assert set_headers["X-Frame-Options"] == "DENY"
        assert "X-XSS-Protection" in set_headers
        assert "Referrer-Policy" in set_headers
        assert "Content-Security-Policy" in set_headers

    def test_security_headers_disabled_via_env(self):
        _, response = self._make_middleware_call(
            env_vars={"AISEC_SECURITY_HEADERS": "false"}
        )
        set_headers = {
            call.args[0]: call.args[1]
            for call in response.__setitem__.call_args_list
        }
        assert "X-Frame-Options" not in set_headers
        assert "Content-Security-Policy" not in set_headers

    def test_hsts_only_on_secure(self):
        """HSTS header should only be set when request.is_secure() is True."""
        from aisec.cli.serve import CorsMiddleware

        mock_response = MagicMock()
        mock_response.__setitem__ = MagicMock()
        mock_response.status_code = 200

        mock_get_response = MagicMock(return_value=mock_response)
        middleware = CorsMiddleware(mock_get_response)

        # Non-secure request
        mock_request = MagicMock()
        mock_request.META = {"REMOTE_ADDR": "127.0.0.1"}
        mock_request.method = "GET"
        mock_request.path = "/api/health/"
        mock_request.is_secure.return_value = False

        with patch.dict(os.environ, {"AISEC_SECURITY_HEADERS": "true"}):
            middleware(mock_request)

        headers_set = {
            call.args[0] for call in mock_response.__setitem__.call_args_list
        }
        assert "Strict-Transport-Security" not in headers_set

    def test_cors_wildcard_default(self):
        _, response = self._make_middleware_call()
        set_headers = {
            call.args[0]: call.args[1]
            for call in response.__setitem__.call_args_list
        }
        assert set_headers.get("Access-Control-Allow-Origin") == "*"

    def test_cors_specific_origin(self):
        from aisec.cli.serve import CorsMiddleware

        mock_response = MagicMock()
        mock_response.__setitem__ = MagicMock()
        mock_response.status_code = 200

        mock_get_response = MagicMock(return_value=mock_response)
        middleware = CorsMiddleware(mock_get_response)

        mock_request = MagicMock()
        mock_request.META = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_ORIGIN": "https://example.com",
        }
        mock_request.method = "GET"
        mock_request.path = "/api/health/"
        mock_request.is_secure.return_value = False

        with patch.dict(os.environ, {"AISEC_ALLOWED_ORIGINS": "https://example.com,https://other.com"}):
            middleware(mock_request)

        set_headers = {
            call.args[0]: call.args[1]
            for call in mock_response.__setitem__.call_args_list
        }
        assert set_headers.get("Access-Control-Allow-Origin") == "https://example.com"
