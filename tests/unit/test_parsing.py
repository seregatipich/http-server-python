"""Unit tests covering HTTP request parsing behavior."""

import pytest

from pyhttpd.adapters.logging import (
    clear_correlation_id,
    get_correlation_id,
)
from pyhttpd.adapters.transport import (
    determine_content_length,
    parse_headers,
    parse_request_line,
    receive_request,
)
from pyhttpd.domain import ForbiddenPath, HttpRequest, RequestEntityTooLarge


class FakeSocket:
    """Minimal socket stub that returns predefined chunks sequentially."""

    def __init__(self, chunks):
        self._chunks = [
            chunk if isinstance(chunk, bytes) else chunk.encode() for chunk in chunks
        ]

    def recv(self, _):
        """Return the next chunk or an empty bytes object when exhausted."""

        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self):
        """Mirror socket interface compatibility for completeness."""

        self._chunks.clear()


def test_parse_headers_normalizes_keys_and_skips_invalid_lines():
    """Header parsing should lowercase keys and ignore malformed lines."""

    headers = parse_headers(
        [
            "Content-Length: 10",
            "User-Agent: ExampleClient",
            "Host:localhost",
            "x-custom: value",
            "   : missing-name",
            "invalid-line",
        ]
    )
    assert headers == {
        "content-length": "10",
        "user-agent": "ExampleClient",
        "host": "localhost",
        "x-custom": "value",
    }


def test_receive_request_handles_partial_reads_and_leftover_bytes():
    """Receiving a request must tolerate partial socket reads."""

    request_bytes = (
        b"GET /echo/hello HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"helloEXTRA"
    )
    socket_chunks = [request_bytes[:25], request_bytes[25:50], request_bytes[50:]]
    client = FakeSocket(socket_chunks)
    request, leftover = receive_request(client, b"")
    assert isinstance(request, HttpRequest)
    assert request.path == "/echo/hello"
    assert request.body == b"hello"
    assert leftover == b"EXTRA"


def test_receive_request_returns_none_when_socket_closes_early():
    """If the client disconnects early the parser should return nothing."""

    client = FakeSocket([b"GET / HTTP/1.1\r\n"])
    request, buffer = receive_request(client, b"")
    assert request is None
    assert buffer == b""


def test_parse_request_line_rejects_files_traversal():
    """A '/files/..' traversal target must raise ForbiddenPath."""

    with pytest.raises(ForbiddenPath):
        parse_request_line("GET /files/../etc HTTP/1.1")


def test_parse_request_line_rejects_malformed_line_missing_tokens():
    """A request line missing the method/target/version tokens must raise ValueError."""

    with pytest.raises(ValueError):
        parse_request_line("GETONLY")


def test_determine_content_length_requires_header_for_post():
    """POST without a Content-Length header must raise ValueError."""

    with pytest.raises(ValueError):
        determine_content_length("POST", {})


def test_determine_content_length_rejects_negative_value():
    """A negative Content-Length must raise ValueError."""

    with pytest.raises(ValueError):
        determine_content_length("POST", {"content-length": "-1"})


def test_determine_content_length_rejects_non_integer_value():
    """A non-integer Content-Length must raise ValueError."""

    with pytest.raises(ValueError):
        determine_content_length("POST", {"content-length": "abc"})


def test_determine_content_length_enforces_max_body_bytes():
    """A Content-Length above max_body_bytes must raise RequestEntityTooLarge."""

    with pytest.raises(RequestEntityTooLarge):
        determine_content_length("POST", {"content-length": "11"}, max_body_bytes=10)


def test_receive_request_rejects_body_exceeding_max_body_bytes():
    """A streamed body growing past max_body_bytes must raise RequestEntityTooLarge."""

    request_bytes = (
        b"POST /files/upload HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 10\r\n\r\n"
        b"hello"
    )
    client = FakeSocket([request_bytes, b"world!!!"])
    with pytest.raises(RequestEntityTooLarge):
        receive_request(client, b"", max_body_bytes=5)


def test_determine_content_length_rejects_underscore_separator():
    """Python int() accepts '1_000'; a smuggling-safe parser must reject it."""

    with pytest.raises(ValueError):
        determine_content_length("POST", {"content-length": "1_000"})


def test_determine_content_length_rejects_plus_prefixed_value():
    """A '+'-prefixed Content-Length is non-canonical and must be rejected."""

    with pytest.raises(ValueError):
        determine_content_length("POST", {"content-length": "+5"})


def test_receive_request_rejects_transfer_encoding():
    """A Transfer-Encoding request is rejected; the body is framed by length only."""

    request_bytes = (
        b"POST /files/x HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"hello"
    )
    client = FakeSocket([request_bytes])
    with pytest.raises(ValueError):
        receive_request(client, b"")


def test_receive_request_rejects_conflicting_content_length():
    """Two differing Content-Length headers desync framing and must be rejected."""

    request_bytes = (
        b"POST /files/x HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 6\r\n\r\n"
        b"hello!"
    )
    client = FakeSocket([request_bytes])
    with pytest.raises(ValueError):
        receive_request(client, b"")


def test_receive_request_propagates_incoming_correlation_id():
    """An incoming X-Request-ID header must populate correlation state."""

    clear_correlation_id()
    request_bytes = (
        b"GET /echo/hello HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"X-Request-ID: incoming-correlation-789\r\n\r\n"
    )
    client = FakeSocket([request_bytes])
    try:
        request, leftover = receive_request(client, b"")
        assert isinstance(request, HttpRequest)
        assert get_correlation_id() == "incoming-correlation-789"
        assert leftover == b""
    finally:
        clear_correlation_id()
