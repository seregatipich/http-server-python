"""HPACK variable-length integer coding (RFC 7541 section 5.1)."""

from typing import Tuple


def encode_integer(value: int, prefix_bits: int, prefix: int = 0) -> bytes:
    """Encode an integer with an N-bit prefix, OR-ing in the high prefix bits."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([prefix | value])
    result = bytearray([prefix | max_prefix])
    value -= max_prefix
    while value >= 128:
        result.append((value % 128) + 128)
        value //= 128
    result.append(value)
    return bytes(result)


def decode_integer(data: bytes, offset: int, prefix_bits: int) -> Tuple[int, int]:
    """Decode an N-bit-prefixed integer; return (value, next_offset)."""
    max_prefix = (1 << prefix_bits) - 1
    value = data[offset] & max_prefix
    offset += 1
    if value < max_prefix:
        return value, offset
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset
