"""Unit tests for the WebSocket echo driver (F7)."""

import struct
from typing import Tuple

from pyhttpd.application.handlers.ws_echo import make_ws_echo_driver
from pyhttpd.domain.websocket import (
    OPCODE_CLOSE,
    OPCODE_CONTINUATION,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
)
from tests.unit._helpers import RecordingLogger


class FakeChannel:
    """Channel double serving canned client bytes and recording server bytes."""

    def __init__(self, inbound: bytes) -> None:
        self._inbound = bytearray(inbound)
        self.outbound = bytearray()
        self.closed = False

    def read(self, size: int) -> bytes:
        chunk = bytes(self._inbound[:size])
        del self._inbound[:size]
        return chunk

    def write(self, data: bytes) -> None:
        self.outbound.extend(data)

    def close(self) -> None:
        self.closed = True


class FakeDraining:
    def __init__(self, draining: bool = False) -> None:
        self._draining = draining

    def is_draining(self) -> bool:
        return self._draining

    def should_stop(self) -> bool:
        return False

    def wait_for_workers(self, _timeout: float) -> bool:
        return True


def _client_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    mask = b"\x01\x02\x03\x04"
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    first = (0x80 if fin else 0x00) | opcode
    return struct.pack("!BB", first, 0x80 | len(payload)) + mask + masked


def _parse_server_frame(data: bytes) -> Tuple[int, bytes]:
    first, second = data[0], data[1]
    opcode = first & 0x0F
    length = second & 0x7F
    payload = data[2 : 2 + length]
    return opcode, bytes(payload)


def _run(inbound: bytes, draining: bool = False) -> FakeChannel:
    channel = FakeChannel(inbound)
    make_ws_echo_driver(FakeDraining(draining), RecordingLogger())(channel)
    return channel


def test_echoes_text_frame() -> None:
    channel = _run(_client_frame(OPCODE_TEXT, b"hello"))
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_TEXT
    assert payload == b"hello"
    assert channel.closed is True


def test_ping_is_answered_with_pong() -> None:
    channel = _run(_client_frame(OPCODE_PING, b"ping!"))
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_PONG
    assert payload == b"ping!"


def test_close_is_echoed() -> None:
    channel = _run(_client_frame(OPCODE_CLOSE, struct.pack("!H", 1000)))
    opcode, _payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_CLOSE


def test_invalid_utf8_text_closes_with_1007() -> None:
    channel = _run(_client_frame(OPCODE_TEXT, b"\xff\xfe"))
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_CLOSE
    assert struct.unpack("!H", payload[:2])[0] == 1007


def test_unmasked_client_frame_closes_with_1002() -> None:
    channel = _run(bytes([0x81, 0x02]) + b"hi")
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_CLOSE
    assert struct.unpack("!H", payload[:2])[0] == 1002


def test_fragmented_message_is_reassembled() -> None:
    inbound = _client_frame(OPCODE_TEXT, b"foo", fin=False) + _client_frame(
        OPCODE_CONTINUATION, b"bar", fin=True
    )
    channel = _run(inbound)
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_TEXT
    assert payload == b"foobar"


def test_draining_sends_going_away_close() -> None:
    channel = _run(_client_frame(OPCODE_TEXT, b"hi"), draining=True)
    opcode, payload = _parse_server_frame(bytes(channel.outbound))
    assert opcode == OPCODE_CLOSE
    assert struct.unpack("!H", payload[:2])[0] == 1001
