"""Unit tests for guarded chunked request-body decoding (F1)."""

import pytest

from pyhttpd.adapters.transport.chunked_reader import read_chunked_body
from pyhttpd.adapters.transport.io import _reject_ambiguous_framing
from pyhttpd.domain import RequestEntityTooLarge


class FakeSocket:
    """Socket stub returning predefined chunks; settimeout is a no-op."""

    def __init__(self, chunks):
        self._chunks = [
            chunk if isinstance(chunk, bytes) else chunk.encode() for chunk in chunks
        ]

    def recv(self, _):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def settimeout(self, _seconds):  # pragma: no cover - interface shim
        pass


def test_decodes_single_chunk() -> None:
    client = FakeSocket([b"5\r\nhello\r\n0\r\n\r\n"])
    body, leftover = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"hello"
    assert leftover == b""


def test_decodes_multiple_chunks() -> None:
    client = FakeSocket([b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"])
    body, _ = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"hello world"


def test_handles_partial_reads() -> None:
    stream = b"4\r\nABCD\r\n3\r\nEFG\r\n0\r\n\r\n"
    client = FakeSocket([stream[:3], stream[3:9], stream[9:]])
    body, _ = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"ABCDEFG"


def test_preserves_leftover_after_terminator() -> None:
    client = FakeSocket([b"3\r\nabc\r\n0\r\n\r\nNEXT"])
    body, leftover = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"abc"
    assert leftover == b"NEXT"


def test_ignores_chunk_extensions() -> None:
    client = FakeSocket([b"5;name=value\r\nhello\r\n0\r\n\r\n"])
    body, _ = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"hello"


def test_discards_trailers() -> None:
    client = FakeSocket([b"3\r\nabc\r\n0\r\nX-Trace: 1\r\n\r\n"])
    body, leftover = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"abc"
    assert leftover == b""


def test_enforces_max_body_bytes() -> None:
    client = FakeSocket([b"a\r\n0123456789\r\n0\r\n\r\n"])
    with pytest.raises(RequestEntityTooLarge):
        read_chunked_body(client, b"", max_body_bytes=5)


def test_rejects_non_hex_chunk_size() -> None:
    client = FakeSocket([b"xyz\r\nhello\r\n0\r\n\r\n"])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)


def test_rejects_oversized_chunk_size_line() -> None:
    client = FakeSocket([b"A" * 200 + b"\r\n"])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)


def test_rejects_bad_chunk_terminator() -> None:
    client = FakeSocket([b"3\r\nabcXX0\r\n\r\n"])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)


def test_returns_none_on_early_close() -> None:
    client = FakeSocket([b"5\r\nhel"])
    body, leftover = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body is None
    assert leftover == b""


def test_framing_default_rejects_transfer_encoding() -> None:
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(["Transfer-Encoding: chunked"])


def test_framing_allows_chunked_when_enabled() -> None:
    lines = ["Transfer-Encoding: chunked"]
    assert _reject_ambiguous_framing(lines, allow_chunked=True) is True


def test_framing_rejects_te_with_content_length() -> None:
    lines = ["Transfer-Encoding: chunked", "Content-Length: 5"]
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(lines, allow_chunked=True)


def test_framing_rejects_multi_coding_transfer_encoding() -> None:
    lines = ["Transfer-Encoding: gzip, chunked"]
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(lines, allow_chunked=True)


def test_framing_rejects_duplicate_transfer_encoding() -> None:
    lines = ["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"]
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(lines, allow_chunked=True)


def test_framing_returns_false_for_content_length() -> None:
    assert _reject_ambiguous_framing(["Content-Length: 5"], allow_chunked=True) is False


def test_framing_rejects_identity_coding() -> None:
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(["Transfer-Encoding: identity"], allow_chunked=True)


def test_framing_rejects_repeated_chunked_coding() -> None:
    lines = ["Transfer-Encoding: chunked, chunked"]
    with pytest.raises(ValueError):
        _reject_ambiguous_framing(lines, allow_chunked=True)


def test_rejects_leading_whitespace_in_chunk_size() -> None:
    client = FakeSocket([b" 3\r\nabc\r\n0\r\n\r\n"])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)


def test_rejects_whitespace_before_chunk_extension() -> None:
    client = FakeSocket([b"3 ;ext\r\nabc\r\n0\r\n\r\n"])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)


def test_accepts_chunk_extension_without_whitespace() -> None:
    client = FakeSocket([b"3;ext\r\nabc\r\n0\r\n\r\n"])
    body, _ = read_chunked_body(client, b"", max_body_bytes=1024)
    assert body == b"abc"


def test_trailer_total_capped_across_lines() -> None:
    trailer_line = b"X: " + b"A" * 2500 + b"\r\n"
    stream = b"3\r\nabc\r\n0\r\n" + trailer_line + trailer_line + b"\r\n"
    client = FakeSocket([stream])
    with pytest.raises(ValueError):
        read_chunked_body(client, b"", max_body_bytes=1024)
