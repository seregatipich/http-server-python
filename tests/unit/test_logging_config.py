"""Tests for logging configuration helpers."""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.bootstrap.logging_setup import CorrelationIdFilter, configure_logging


def test_configure_logging_stream_handler(monkeypatch):
    """Configure stdout handler and validate formatter output."""
    monkeypatch.setenv("HTTP_SERVER_LOG_LEVEL", "INFO")
    logger = configure_logging("DEBUG", "stdout")

    assert logger.logger.name == "http_server"
    assert logger.logger.level == logging.DEBUG
    assert len(logger.logger.handlers) == 1

    handler = logger.logger.handlers[0]
    assert isinstance(handler, logging.StreamHandler)
    formatter = handler.formatter
    assert formatter is not None
    record = logging.LogRecord(
        name="http_server.server",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=0,
        msg="format test",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "test-id-123"
    record.component = "server"
    formatted = formatter.format(record)
    log_data = json.loads(formatted)
    assert log_data["component"] == "server"
    assert log_data["message"] == "format test"
    assert log_data["correlation_id"] == "test-id-123"


def test_configure_logging_file_destination(tmp_path: Path):
    """Configure file handler and verify writes are persisted."""
    destination = tmp_path / "server.log"
    logger = configure_logging("WARNING", destination.as_posix())

    assert logger.logger.level == logging.WARNING
    handler = logger.logger.handlers[0]
    assert handler.baseFilename == destination.as_posix()

    server_logger = logging.getLogger("http_server.server")
    server_logger.warning("file log test")

    handler.flush()
    contents = destination.read_text()
    assert "file log test" in contents


def test_correlation_id_filter_inserts_placeholder_when_missing():
    """Filter should default correlation_id to '-' for bare records."""

    log_filter = CorrelationIdFilter()
    record = logging.LogRecord(
        name="http_server.server",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="missing id",
        args=(),
        exc_info=None,
    )

    assert not hasattr(record, "correlation_id")
    assert log_filter.filter(record)
    assert record.correlation_id == "-"


def test_configure_logging_emits_event():
    """Test that configure_logging emits a 'logging_configured' event."""

    with patch("server.bootstrap.logging_setup._build_handler") as mock_build:
        mock_handler = MagicMock()
        mock_handler.level = logging.INFO  # Fix comparison error
        mock_build.return_value = mock_handler

        configure_logging("INFO", "stdout")

        # Check if the handler received the record
        assert mock_handler.handle.called
        # Get the record passed to handle()
        record = mock_handler.handle.call_args[0][0]

        assert record.msg == "Logging configured"
        assert record.levelno == logging.INFO
        assert getattr(record, "event", None) == "logging_configured"
        assert getattr(record, "destination", None) == "stdout"
        assert getattr(record, "use_json", None) is True
