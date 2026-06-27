"""WebSocket echo driver run over a taken-over Channel.

Reads masked client frames, reassembles fragmented data messages, answers
control frames (ping->pong, close handshake), validates UTF-8 on text, and
echoes data back unmasked. A protocol violation or oversize message ends the
session with the appropriate Close code; a graceful shutdown sends Close 1001.
"""

import logging
import struct
from typing import Callable, Optional, Tuple

from pyhttpd.domain import Channel, DrainingState, Logger
from pyhttpd.domain.websocket import (
    MAX_PAYLOAD_BYTES,
    OPCODE_CLOSE,
    OPCODE_CONTINUATION,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
    Frame,
    decode_frame,
    encode_frame,
)

CLOSE_GOING_AWAY = 1001
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_INVALID_PAYLOAD = 1007
READ_SIZE = 4096


class _FrameStream:
    """Buffers Channel reads and yields one decoded frame at a time."""

    def __init__(self, channel: Channel) -> None:
        self._channel = channel
        self._buffer = bytearray()

    def next_frame(self) -> Optional[Frame]:
        """Return the next complete frame, or None when the peer disconnects."""
        while True:
            decoded = decode_frame(bytes(self._buffer))
            if decoded is not None:
                frame, consumed = decoded
                del self._buffer[:consumed]
                return frame
            chunk = self._channel.read(READ_SIZE)
            if not chunk:
                return None
            self._buffer.extend(chunk)


class _MessageAssembler:
    """Reassembles fragmented data frames into a complete message."""

    def __init__(self) -> None:
        self._opcode: Optional[int] = None
        self._payload = bytearray()

    def add(self, frame: Frame) -> Optional[Tuple[int, bytes]]:
        """Fold a data frame in; return (opcode, payload) once the message is final."""
        if frame.opcode == OPCODE_CONTINUATION:
            if self._opcode is None:
                raise ValueError("continuation frame without an open message")
        elif self._opcode is not None:
            raise ValueError("new data frame during fragmentation")
        else:
            self._opcode = frame.opcode
        self._payload.extend(frame.payload)
        if len(self._payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("reassembled message exceeds limit")
        if not frame.fin:
            return None
        message = (self._opcode, bytes(self._payload))
        self._opcode = None
        self._payload = bytearray()
        return message


def make_ws_echo_driver(
    draining_state: Optional[DrainingState], logger: Logger
) -> Callable[[Channel], None]:
    """Build the upgrade driver that runs the echo protocol over a Channel."""

    def drive(channel: Channel) -> None:
        try:
            _run_echo(channel, draining_state)
        except ValueError:
            _send_close(channel, CLOSE_PROTOCOL_ERROR)
        except (OSError, ConnectionError):
            pass
        finally:
            logger.log(logging.DEBUG, "websocket_closed")
            channel.close()

    return drive


def _run_echo(channel: Channel, draining_state: Optional[DrainingState]) -> None:
    stream = _FrameStream(channel)
    assembler = _MessageAssembler()
    while True:
        frame = stream.next_frame()
        if frame is None:
            return
        if draining_state is not None and draining_state.is_draining():
            _send_close(channel, CLOSE_GOING_AWAY)
            return
        if frame.opcode == OPCODE_CLOSE:
            channel.write(encode_frame(OPCODE_CLOSE, frame.payload))
            return
        if frame.opcode == OPCODE_PING:
            channel.write(encode_frame(OPCODE_PONG, frame.payload))
            continue
        if frame.opcode == OPCODE_PONG:
            continue
        if not _echo_message(channel, assembler.add(frame)):
            return


def _echo_message(channel: Channel, message: Optional[Tuple[int, bytes]]) -> bool:
    if message is None:
        return True
    opcode, payload = message
    if opcode == OPCODE_TEXT and not _is_valid_utf8(payload):
        _send_close(channel, CLOSE_INVALID_PAYLOAD)
        return False
    channel.write(encode_frame(opcode, payload))
    return True


def _is_valid_utf8(payload: bytes) -> bool:
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _send_close(channel: Channel, code: int) -> None:
    channel.write(encode_frame(OPCODE_CLOSE, struct.pack("!H", code)))
