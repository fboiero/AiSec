"""Tests for scan queue, concurrency control, and cancellation."""

from concurrent.futures import Future
from unittest.mock import MagicMock, patch

import pytest


class TestGetExecutor:
    @patch("aisec.cli.serve._executor", None)
    def test_creates_thread_pool(self):
        from aisec.cli.serve import _get_executor
        executor = _get_executor()
        assert executor is not None
        assert hasattr(executor, "submit")
        # Clean up
        executor.shutdown(wait=False)

    @patch("aisec.cli.serve._executor", None)
    @patch("aisec.core.config.AiSecConfig")
    def test_respects_max_concurrent_scans(self, mock_config):
        mock_config.return_value.max_concurrent_scans = 2
        from aisec.cli.serve import _get_executor
        executor = _get_executor()
        assert executor._max_workers == 2
        executor.shutdown(wait=False)


class TestGetHistory:
    @patch("aisec.cli.serve._history", None)
    def test_creates_history_singleton(self, tmp_path):
        with patch("aisec.core.history.ScanHistory") as MockHistory:
            MockHistory.return_value = MagicMock()
            from aisec.cli.serve import _get_history
            history = _get_history()
            assert history is not None
            MockHistory.assert_called_once()


class TestGracefulShutdown:
    def test_shutdown_closes_resources(self):
        from aisec.cli.serve import _graceful_shutdown
        import aisec.cli.serve as serve_module

        mock_executor = MagicMock()
        mock_history = MagicMock()
        serve_module._executor = mock_executor
        serve_module._history = mock_history

        _graceful_shutdown()

        mock_executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
        mock_history.close.assert_called_once()
        assert serve_module._executor is None
        assert serve_module._history is None


class TestScanFutures:
    def test_future_tracking(self):
        from aisec.cli.serve import _scan_futures
        future = Future()
        _scan_futures["test-scan"] = future
        assert "test-scan" in _scan_futures
        assert not future.done()
        # Clean up
        del _scan_futures["test-scan"]
