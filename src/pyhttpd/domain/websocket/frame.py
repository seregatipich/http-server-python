"""RFC 6455 WebSocket frame codec (pure, IO-free).

The decoder works on an in-memory buffer so the transport loop owns all reads:
it returns None when more bytes are needed and raises ValueError on a protocol
violation (unmasked client frame, reserved bits, oversize, or malformed control
frame). The encoder produces server frames, which are never masked.
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

MAX_PAYLOAD_BYTES = 1 << 20


@dataclass(frozen=True)
class Frame:
    """A decoded WebSocket frame."""

    fin: bool
    opcode: int
    payload: bytes


def is_control_opcode(opcode: int) -> bool:
    """Return whether the opcode denotes a control frame."""
    return opcode >= OPCODE_CLOSE


def encode_frame(opcode: int, payload: bytes = b"", fin: bool = True) -> bytes:
    """Encode an unmasked server frame."""
    first = (0x80 if fin else 0x00) | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", first, length)
    elif length < (1 << 16):
        header = struct.pack("!BBH", first, 126, length)
    else:
        header = struct.pack("!BBQ", first, 127, length)
    return header + payload


def decode_frame(buffer: bytes) -> Optional[Tuple[Frame, int]]:
    """Decode one frame, returning (frame, bytes_consumed) or None if incomplete."""
    if len(buffer) < 2:
        return None
    first, second = buffer[0], buffer[1]
    if first & 0x70:
        raise ValueError("reserved bits must be zero")
    if not second & 0x80:
        raise ValueError("client frames must be masked")
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    length, offset = _decode_length(buffer, second & 0x7F)
    if length is None:
        return None
    if length > MAX_PAYLOAD_BYTES:
        raise ValueError("frame payload exceeds limit")
    if is_control_opcode(opcode) and (length > 125 or not fin):
        raise ValueError("invalid control frame")
    if len(buffer) < offset + 4 + length:
        return None
    mask = buffer[offset : offset + 4]
    payload = _unmask(buffer[offset + 4 : offset + 4 + length], mask)
    return Frame(fin, opcode, payload), offset + 4 + length


def _decode_length(buffer: bytes, indicator: int) -> Tuple[Optional[int], int]:
    if indicator == 126:
        if len(buffer) < 4:
            return None, 4
        return struct.unpack_from("!H", buffer, 2)[0], 4
    if indicator == 127:
        if len(buffer) < 10:
            return None, 10
        return struct.unpack_from("!Q", buffer, 2)[0], 10
    return indicator, 2


def _unmask(data: bytes, mask: bytes) -> bytes:
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
