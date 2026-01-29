"""Tests for logging configuration helpers."""

import logging
from pathlib import Path

from logging_config import CorrelationIdFilter, configure_logging


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
    formatted = formatter.format(record)
    assert "http_server.server" in formatted
    assert "format test" in formatted


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
