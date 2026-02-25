"""Tests for structured error responses and new exception types."""

from aisec.core.exceptions import (
    AiSecError,
    QueueFullError,
    ValidationError,
    WebhookError,
    error_response,
)


class TestErrorResponse:
    def test_basic_structure(self):
        result = error_response("SCAN_NOT_FOUND", "Scan xyz not found")
        assert result == {
            "error": {"code": "SCAN_NOT_FOUND", "message": "Scan xyz not found"}
        }

    def test_with_details(self):
        result = error_response(
            "VALIDATION_ERROR", "Bad input", {"field": "url"}
        )
        assert result["error"]["details"] == {"field": "url"}

    def test_no_details_key_when_none(self):
        result = error_response("ERR", "msg")
        assert "details" not in result["error"]


class TestQueueFullError:
    def test_message_format(self):
        err = QueueFullError(16, 16)
        assert "16/16" in str(err)
        assert err.queue_size == 16
        assert err.max_size == 16

    def test_is_aisec_error(self):
        assert issubclass(QueueFullError, AiSecError)


class TestWebhookError:
    def test_is_aisec_error(self):
        assert issubclass(WebhookError, AiSecError)

    def test_message(self):
        err = WebhookError("delivery failed")
        assert "delivery failed" in str(err)


class TestValidationError:
    def test_field_attribute(self):
        err = ValidationError("url", "bad scheme")
        assert err.field == "url"
        assert "url" in str(err)
        assert "bad scheme" in str(err)

    def test_is_aisec_error(self):
        assert issubclass(ValidationError, AiSecError)
