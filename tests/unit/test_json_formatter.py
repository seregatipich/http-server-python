"""Unit tests for JSON formatter."""

import json
import logging
import sys

import pytest

from pyhttpd.bootstrap import JsonFormatter


@pytest.fixture(name="json_formatter")
def json_formatter_fixture():
    """Create a JSON formatter instance."""
    return JsonFormatter("%Y-%m-%d %H:%M:%S")


def make_record(level=logging.INFO, msg="Test message", exc_info=None, **attrs):
    """Create a LogRecord with common test defaults."""
    record = logging.LogRecord(
        name="http_server.test",
        level=level,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=(),
        exc_info=exc_info,
    )
    for name, value in attrs.items():
        setattr(record, name, value)
    return record


def formatted_log(json_formatter, record):
    """Format a record and decode the JSON payload."""
    return json.loads(json_formatter.format(record))


def test_json_formatter_basic_fields(json_formatter):
    """Test that JSON formatter includes all required basic fields."""
    record = make_record(
        correlation_id="test-correlation-id",
        component="test",
    )
    log_data = formatted_log(json_formatter, record)

    assert log_data["level"] == "INFO"
    assert log_data["correlation_id"] == "test-correlation-id"
    assert log_data["component"] == "test"
    assert log_data["message"] == "Test message"
    assert "timestamp" in log_data


def test_json_formatter_with_event(json_formatter):
    """Test that JSON formatter includes event field when present."""
    record = make_record(
        correlation_id="test-id",
        component="test",
        event="test_event",
    )
    log_data = formatted_log(json_formatter, record)

    assert log_data["event"] == "test_event"


def test_json_formatter_with_extra_fields(json_formatter):
    """Test that JSON formatter includes extra fields."""
    record = make_record(
        correlation_id="test-id",
        component="test",
        client="127.0.0.1:8080",
        status_code=200,
        duration_ms=15.5,
    )
    log_data = formatted_log(json_formatter, record)

    assert log_data["client"] == "127.0.0.1:8080"
    assert log_data["status_code"] == 200
    assert log_data["duration_ms"] == 15.5


def test_json_formatter_default_correlation_id(json_formatter):
    """Test that JSON formatter defaults correlation_id to '-' when missing."""
    record = make_record(component="test")
    log_data = formatted_log(json_formatter, record)

    assert log_data["correlation_id"] == "-"


def test_json_formatter_default_component(json_formatter):
    """Test that JSON formatter defaults component to 'unknown' when missing."""
    record = make_record(correlation_id="test-id")
    log_data = formatted_log(json_formatter, record)

    assert log_data["component"] == "unknown"


def test_json_formatter_stable_key_ordering(json_formatter):
    """Test that JSON formatter produces stable key ordering."""
    record = make_record(
        correlation_id="test-id",
        component="test",
        event="test_event",
        client="127.0.0.1:8080",
    )

    output1 = json_formatter.format(record)
    output2 = json_formatter.format(record)

    assert output1 == output2

    log_data = json.loads(output1)
    keys = list(log_data.keys())
    assert keys == sorted(keys)


def test_json_formatter_with_exception(json_formatter):
    """Test that JSON formatter includes exception information."""
    try:
        raise ValueError("Test error")
    except ValueError:
        record = make_record(
            level=logging.ERROR,
            exc_info=sys.exc_info(),
            correlation_id="test-id",
            component="test",
        )
        log_data = formatted_log(json_formatter, record)

        assert "exception" in log_data
        assert "ValueError: Test error" in log_data["exception"]
