"""Unit tests for the WebSocket frame codec and handshake (F7)."""

import struct

import pytest

from pyhttpd.domain.websocket import (
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_TEXT,
    compute_accept,
    decode_frame,
    encode_frame,
    is_websocket_upgrade,
)

# RFC 6455 section 5.7: a single-frame masked "Hello" from client to server.
MASKED_HELLO = bytes([0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58])


def test_encode_unmasked_text_matches_rfc_example() -> None:
    assert encode_frame(OPCODE_TEXT, b"Hello") == bytes([0x81, 0x05]) + b"Hello"


def test_encode_extended_16bit_length() -> None:
    payload = b"\x00" * 200
    frame = encode_frame(OPCODE_TEXT, payload)
    assert frame[:2] == bytes([0x81, 126])
    assert struct.unpack_from("!H", frame, 2)[0] == 200


def test_decode_masked_hello() -> None:
    decoded = decode_frame(MASKED_HELLO)
    assert decoded is not None
    frame, consumed = decoded
    assert frame.opcode == OPCODE_TEXT
    assert frame.fin is True
    assert frame.payload == b"Hello"
    assert consumed == len(MASKED_HELLO)


def test_decode_rejects_unmasked_client_frame() -> None:
    with pytest.raises(ValueError):
        decode_frame(bytes([0x81, 0x05]) + b"Hello")


def test_decode_returns_none_when_incomplete() -> None:
    assert decode_frame(MASKED_HELLO[:4]) is None


def test_decode_rejects_reserved_bits() -> None:
    with pytest.raises(ValueError):
        decode_frame(bytes([0xC1, 0x80, 0x00, 0x00, 0x00, 0x00]))


def test_decode_rejects_fragmented_control_frame() -> None:
    # FIN=0 on a PING (control) frame is illegal.
    with pytest.raises(ValueError):
        decode_frame(bytes([0x09, 0x80, 0x00, 0x00, 0x00, 0x00]))


def test_decode_rejects_oversize_control_frame() -> None:
    # A close frame claiming 126 bytes violates the 125-byte control limit.
    header = bytes([0x88, 0x80 | 126]) + struct.pack("!H", 200)
    with pytest.raises(ValueError):
        decode_frame(header + b"\x00\x00\x00\x00" + b"x" * 200)


def test_decode_round_trips_leftover_for_pipelined_frames() -> None:
    decoded = decode_frame(MASKED_HELLO + b"leftover")
    assert decoded is not None
    _frame, consumed = decoded
    assert MASKED_HELLO[consumed:] == b""


def test_compute_accept_matches_rfc_example() -> None:
    assert compute_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_is_websocket_upgrade_accepts_valid_headers() -> None:
    assert is_websocket_upgrade(
        {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-version": "13",
            "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
    )


def test_is_websocket_upgrade_rejects_missing_key() -> None:
    assert not is_websocket_upgrade(
        {"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-version": "13"}
    )


def test_close_opcode_is_control() -> None:
    frame = encode_frame(OPCODE_CLOSE, b"\x03\xe9")
    assert frame[0] & 0x0F == OPCODE_CLOSE
    assert encode_frame(OPCODE_PING)[0] & 0x0F == OPCODE_PING
