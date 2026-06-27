"""HTTP/2 frame codec (RFC 7540 section 4)."""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

FRAME_HEADER_SIZE = 9

DATA = 0x0
HEADERS = 0x1
PRIORITY = 0x2
RST_STREAM = 0x3
SETTINGS = 0x4
PUSH_PROMISE = 0x5
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass(frozen=True)
class Frame:
    """A decoded HTTP/2 frame."""

    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


def encode_frame(
    frame_type: int, flags: int, stream_id: int, payload: bytes = b""
) -> bytes:
    """Encode an HTTP/2 frame with its 9-byte header."""
    header = (
        len(payload).to_bytes(3, "big")
        + struct.pack("!BB", frame_type, flags)
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
    )
    return header + payload


def decode_frame(buffer: bytes) -> Optional[Tuple[Frame, int]]:
    """Decode one frame, returning (frame, bytes_consumed) or None if incomplete."""
    if len(buffer) < FRAME_HEADER_SIZE:
        return None
    length = int.from_bytes(buffer[0:3], "big")
    frame_type = buffer[3]
    flags = buffer[4]
    stream_id = struct.unpack("!I", buffer[5:9])[0] & 0x7FFFFFFF
    end = FRAME_HEADER_SIZE + length
    if len(buffer) < end:
        return None
    return Frame(frame_type, flags, stream_id, buffer[FRAME_HEADER_SIZE:end]), end
