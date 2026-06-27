"""Incremental decoder for Transfer-Encoding: chunked request bodies.

Decoding is opt-in (the default read path rejects Transfer-Encoding to foreclose
request smuggling). Every limit is enforced against the same ``max_body_bytes``
budget as Content-Length framing, and chunk-size lines are length-capped so a
malicious client cannot exhaust memory before the size is parsed.
"""

import socket
from typing import Optional

from pyhttpd.adapters.transport.deadline import _deadline_ns, _recv_with_deadline
from pyhttpd.domain import PhaseTimeouts, RequestEntityTooLarge

MAX_CHUNK_SIZE_LINE = 64
MAX_TRAILER_BYTES = 4096
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


class _ChunkedReader:
    """Buffered reader that pulls chunked-encoded bytes off a socket."""

    def __init__(
        self,
        client_socket: socket.socket,
        buffer: bytes,
        deadline: Optional[int],
    ) -> None:
        self._socket = client_socket
        self._buffer = bytearray(buffer)
        self._deadline = deadline

    def _pull(self) -> bool:
        if self._deadline is not None:
            chunk = _recv_with_deadline(self._socket, self._deadline)
        else:
            chunk = self._socket.recv(4096)
        if not chunk:
            return False
        self._buffer.extend(chunk)
        return True

    def read_line(self, cap: int) -> Optional[bytes]:
        """Return the next CRLF-terminated line (without CRLF), or None on EOF."""
        while b"\r\n" not in self._buffer:
            if len(self._buffer) > cap:
                raise ValueError("chunk header exceeds limit")
            if not self._pull():
                return None
        line, _, rest = self._buffer.partition(b"\r\n")
        if len(line) > cap:
            raise ValueError("chunk header exceeds limit")
        self._buffer = bytearray(rest)
        return bytes(line)

    def read_exact(self, count: int) -> Optional[bytes]:
        """Return exactly ``count`` bytes, or None if the socket closes first."""
        while len(self._buffer) < count:
            if not self._pull():
                return None
        taken = bytes(self._buffer[:count])
        self._buffer = bytearray(self._buffer[count:])
        return taken

    def remaining(self) -> bytes:
        """Return any buffered bytes left after the chunked body."""
        return bytes(self._buffer)


def _parse_chunk_size(token: bytes) -> int:
    if not token or any(byte not in _HEX_DIGITS for byte in token):
        raise ValueError("invalid chunk size")
    return int(token, 16)


def _consume_trailers(reader: _ChunkedReader) -> Optional[bool]:
    total = 0
    while True:
        line = reader.read_line(MAX_TRAILER_BYTES)
        if line is None:
            return None
        if not line:
            return True
        total += len(line)
        if total > MAX_TRAILER_BYTES:
            raise ValueError("trailer section exceeds limit")


def read_chunked_body(
    client_socket: socket.socket,
    buffer: bytes,
    max_body_bytes: int,
    timeouts: Optional[PhaseTimeouts] = None,
) -> tuple[Optional[bytes], bytes]:
    """Decode a chunked request body, returning (body, leftover) or (None, b"")."""
    deadline = (
        _deadline_ns(timeouts.body_read_seconds) if timeouts is not None else None
    )
    reader = _ChunkedReader(client_socket, buffer, deadline)
    body = bytearray()
    while True:
        size_line = reader.read_line(MAX_CHUNK_SIZE_LINE)
        if size_line is None:
            return None, b""
        chunk_size = _parse_chunk_size(size_line.split(b";", 1)[0].strip())
        if chunk_size == 0:
            if _consume_trailers(reader) is None:
                return None, b""
            return bytes(body), reader.remaining()
        if len(body) + chunk_size > max_body_bytes:
            raise RequestEntityTooLarge
        chunk = reader.read_exact(chunk_size + 2)
        if chunk is None:
            return None, b""
        if chunk[chunk_size:] != b"\r\n":
            raise ValueError("malformed chunk terminator")
        body.extend(chunk[:chunk_size])
