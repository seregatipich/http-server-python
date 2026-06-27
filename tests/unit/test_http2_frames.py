"""Unit tests for the HTTP/2 frame codec (F13)."""

from pyhttpd.domain.http2.frames import (
    DATA,
    FLAG_ACK,
    FLAG_END_STREAM,
    SETTINGS,
    decode_frame,
    encode_frame,
)


def test_encode_decode_round_trip() -> None:
    encoded = encode_frame(SETTINGS, FLAG_ACK, 0)
    decoded = decode_frame(encoded)
    assert decoded is not None
    frame, consumed = decoded
    assert frame.frame_type == SETTINGS
    assert frame.flags == FLAG_ACK
    assert frame.stream_id == 0
    assert frame.payload == b""
    assert consumed == len(encoded)


def test_data_frame_carries_payload_and_stream() -> None:
    encoded = encode_frame(DATA, FLAG_END_STREAM, 5, b"hello")
    decoded = decode_frame(encoded)
    assert decoded is not None
    frame, consumed = decoded
    assert frame.frame_type == DATA
    assert frame.stream_id == 5
    assert frame.flags == FLAG_END_STREAM
    assert frame.payload == b"hello"
    assert consumed == 9 + 5


def test_decode_incomplete_header_returns_none() -> None:
    assert decode_frame(b"\x00\x00") is None


def test_decode_incomplete_payload_returns_none() -> None:
    # Declares 5 bytes of payload but only provides 2.
    encoded = encode_frame(DATA, 0, 1, b"hello")
    assert decode_frame(encoded[:-3]) is None


def test_decode_leaves_trailing_bytes() -> None:
    encoded = encode_frame(SETTINGS, 0, 0) + b"trailing"
    decoded = decode_frame(encoded)
    assert decoded is not None
    _frame, consumed = decoded
    assert encoded[consumed:] == b"trailing"


def test_reserved_bit_is_masked_from_stream_id() -> None:
    encoded = encode_frame(DATA, 0, 1, b"x")
    framed = bytearray(encoded)
    framed[5] |= 0x80  # set the reserved high bit
    decoded = decode_frame(bytes(framed))
    assert decoded is not None
    frame, _consumed = decoded
    assert frame.stream_id == 1
