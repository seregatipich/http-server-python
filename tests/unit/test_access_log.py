"""Unit tests for Combined Log Format access logging (F11b)."""

import logging

from pyhttpd.adapters.logging.access_log import (
    AccessLogger,
    _body_size,
    _status_code,
    combined_log_line,
)
from pyhttpd.domain import HttpResponse
from tests.unit._helpers import make_request


def test_combined_log_line_full_format() -> None:
    request = make_request(
        path="/echo/hi", headers={"referer": "http://x", "user-agent": "curl/8"}
    )
    line = combined_log_line(
        "1.2.3.4", request, 200, "11", "10/Oct/2000:13:55:36 +0000"
    )
    assert line == (
        "1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "
        '"GET /echo/hi HTTP/1.1" 200 11 "http://x" "curl/8"'
    )


def test_combined_log_line_includes_query() -> None:
    request = make_request(path="/search", query="q=1")
    line = combined_log_line("1.2.3.4", request, 200, "0", "ts")
    assert '"GET /search?q=1 HTTP/1.1"' in line


def test_combined_log_line_defaults_missing_fields_to_dash() -> None:
    line = combined_log_line("1.2.3.4", make_request(), 404, "-", "ts")
    assert line.endswith('"-" "-"')


def test_status_code_parsed_from_status_line() -> None:
    assert _status_code("HTTP/1.1 404 Not Found") == 404


def test_body_size_uses_known_length() -> None:
    response = HttpResponse("HTTP/1.1 200 OK", {}, b"hello", False)
    assert _body_size(response) == "5"


def test_body_size_is_dash_for_streaming() -> None:
    response = HttpResponse(
        "HTTP/1.1 200 OK", {}, b"", False, streaming=True, use_chunked=True
    )
    assert _body_size(response) == "-"


def test_access_logger_records_line() -> None:
    records: list[str] = []
    logger = logging.getLogger("pyhttpd.access.unit")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.addHandler(_ListHandler(records))

    AccessLogger(logger).record(
        "9.9.9.9",
        make_request(path="/x"),
        HttpResponse("HTTP/1.1 200 OK", {}, b"ok", False),
    )
    assert any('"GET /x HTTP/1.1" 200 2' in line for line in records)
    assert any("9.9.9.9" in line for line in records)


class _ListHandler(logging.Handler):
    def __init__(self, sink: list) -> None:
        super().__init__()
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self._sink.append(record.getMessage())
