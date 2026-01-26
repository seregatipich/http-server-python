import logging
from pathlib import Path

from logging_config import configure_logging


def test_configure_logging_stream_handler(monkeypatch):
    monkeypatch.setenv("HTTP_SERVER_LOG_LEVEL", "INFO")
    logger = configure_logging("DEBUG", "stdout")

    assert logger.name == "http_server"
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1

    handler = logger.handlers[0]
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
    formatted = formatter.format(record)
    assert "http_server.server" in formatted
    assert "format test" in formatted


def test_configure_logging_file_destination(tmp_path: Path):
    destination = tmp_path / "server.log"
    logger = configure_logging("WARNING", destination.as_posix())

    assert logger.level == logging.WARNING
    handler = logger.handlers[0]
    assert handler.baseFilename == destination.as_posix()

    server_logger = logging.getLogger("http_server.server")
    server_logger.warning("file log test")

    handler.flush()
    contents = destination.read_text()
    assert "file log test" in contents
