"""Unit tests for CorrelationLoggerAdapter."""

import logging

import pytest

from server.domain.correlation_id import (
    CorrelationLoggerAdapter,
    clear_correlation_id,
    set_correlation_id,
)


@pytest.fixture(name="logger_adapter")
def logger_adapter_fixture():
    """Create a CorrelationLoggerAdapter instance."""
    base_logger = logging.getLogger("http_server.test")
    return CorrelationLoggerAdapter(base_logger, {})


def test_adapter_injects_correlation_id(logger_adapter):
    """Test that adapter injects correlation_id from context."""
    set_correlation_id("test-correlation-123")

    _, kwargs = logger_adapter.process("Test message", {})

    assert "extra" in kwargs
    assert kwargs["extra"]["correlation_id"] == "test-correlation-123"

    clear_correlation_id()


def test_adapter_defaults_correlation_id_when_missing(logger_adapter):
    """Test that adapter defaults correlation_id to '-' when not set."""
    clear_correlation_id()

    _, kwargs = logger_adapter.process("Test message", {})

    assert "extra" in kwargs
    assert kwargs["extra"]["correlation_id"] == "-"


def test_adapter_extracts_component_from_logger_name(logger_adapter):
    """Test that adapter extracts component from logger name."""
    _, kwargs = logger_adapter.process("Test message", {})

    assert "extra" in kwargs
    assert kwargs["extra"]["component"] == "test"


def test_adapter_preserves_existing_extra_fields(logger_adapter):
    """Test that adapter preserves existing extra fields."""
    set_correlation_id("test-id")

    _, kwargs = logger_adapter.process(
        "Test message", {"extra": {"custom_field": "custom_value", "status_code": 200}}
    )

    assert kwargs["extra"]["correlation_id"] == "test-id"
    assert kwargs["extra"]["component"] == "test"
    assert kwargs["extra"]["custom_field"] == "custom_value"
    assert kwargs["extra"]["status_code"] == 200

    clear_correlation_id()


def test_adapter_handles_non_http_server_logger():
    """Test that adapter handles logger names not starting with http_server."""
    base_logger = logging.getLogger("other.module")
    adapter = CorrelationLoggerAdapter(base_logger, {})

    _, kwargs = adapter.process("Test message", {})

    assert kwargs["extra"]["component"] == "other.module"


def test_adapter_with_nested_component():
    """Test that adapter correctly extracts nested component names."""
    base_logger = logging.getLogger("http_server.transport.worker")
    adapter = CorrelationLoggerAdapter(base_logger, {})

    _, kwargs = adapter.process("Test message", {})

    assert kwargs["extra"]["component"] == "transport.worker"


def test_adapter_message_unchanged(logger_adapter):
    """Test that adapter does not modify the message."""
    original_msg = "Test message with {placeholder}"

    msg, _ = logger_adapter.process(original_msg, {})

    assert msg == original_msg


def test_adapter_creates_extra_dict_when_missing(logger_adapter):
    """Test that adapter creates extra dict when not present in kwargs."""
    _, kwargs = logger_adapter.process("Test message", {})

    assert "extra" in kwargs
    assert isinstance(kwargs["extra"], dict)


def test_adapter_with_event_in_extra(logger_adapter):
    """Test that adapter preserves event field in extra."""
    set_correlation_id("test-id")

    _, kwargs = logger_adapter.process(
        "Test message", {"extra": {"event": "test_event"}}
    )

    assert kwargs["extra"]["event"] == "test_event"
    assert kwargs["extra"]["correlation_id"] == "test-id"
    assert kwargs["extra"]["component"] == "test"

    clear_correlation_id()
