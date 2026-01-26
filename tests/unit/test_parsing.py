"""Unit tests covering HTTP request parsing behavior."""

from main import HttpRequest, parse_headers, receive_request


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
            "x-custom: value",
            "invalid-line",
        ]
    )
    assert headers == {
        "content-length": "10",
        "user-agent": "ExampleClient",
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
