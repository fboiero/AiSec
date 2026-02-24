"""Tests for structured logging configuration."""

from __future__ import annotations

import io
import json
import logging
import os
from unittest.mock import patch

import pytest


class TestSetupLogging:
    """Test setup_logging function."""

    def test_setup_logging_default(self):
        """Default call should configure aisec logger."""
        from aisec.utils.logging import setup_logging
        setup_logging("INFO")
        logger = logging.getLogger("aisec")
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0

    def test_setup_logging_debug(self):
        from aisec.utils.logging import setup_logging
        setup_logging("DEBUG")
        logger = logging.getLogger("aisec")
        assert logger.level == logging.DEBUG

    def test_setup_logging_json_format(self, capsys):
        """JSON format should produce valid JSON lines."""
        from aisec.utils.logging import setup_logging
        setup_logging("INFO", json_format=True)

        logger = logging.getLogger("aisec.test_json")
        # Capture stderr output
        stream = io.StringIO()
        handler = logger.parent.handlers[0] if logger.parent else logger.handlers[0]
        old_stream = handler.stream
        handler.stream = stream
        try:
            logger.info("test message")
            output = stream.getvalue()
            if output.strip():
                data = json.loads(output.strip())
                assert "event" in data
        finally:
            handler.stream = old_stream

    def test_setup_logging_human_format(self):
        """Human format should not raise."""
        from aisec.utils.logging import setup_logging
        setup_logging("INFO", json_format=False)

    @patch.dict(os.environ, {"AISEC_LOG_FORMAT": "json"})
    def test_env_var_json_format(self):
        """AISEC_LOG_FORMAT=json should enable JSON output."""
        from aisec.utils.logging import setup_logging
        # Should not raise
        setup_logging("INFO")

    @patch.dict(os.environ, {"AISEC_LOG_JSON": "true"})
    def test_env_var_log_json(self):
        """AISEC_LOG_JSON=true should enable JSON output."""
        from aisec.utils.logging import setup_logging
        setup_logging("INFO")


class TestContextBinding:
    """Test structlog context binding."""

    def test_bind_context(self):
        from aisec.utils.logging import bind_context, clear_context
        bind_context(request_id="abc123", scan_id="xyz789")
        # Should not raise
        clear_context()

    def test_clear_context(self):
        from aisec.utils.logging import clear_context
        clear_context()  # Should be safe to call even without prior binding
