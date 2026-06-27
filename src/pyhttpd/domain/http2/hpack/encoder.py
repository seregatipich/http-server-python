"""HPACK header block encoder (RFC 7541 section 6).

Emits indexed fields for exact static-table matches and literal-without-indexing
fields otherwise, with raw (non-Huffman) string literals. This is valid HPACK
that any decoder accepts; it keeps the encoder simple and stateless.
"""

from typing import Dict, List, Tuple

from pyhttpd.domain.http2.hpack.integer import encode_integer
from pyhttpd.domain.http2.hpack.static_table import STATIC_TABLE

Header = Tuple[str, str]

_STATIC_FULL: Dict[Header, int] = {}
_STATIC_NAMES: Dict[str, int] = {}
for _position, (_name, _value) in enumerate(STATIC_TABLE, start=1):
    _STATIC_FULL.setdefault((_name, _value), _position)
    _STATIC_NAMES.setdefault(_name, _position)


def encode_headers(headers: List[Header]) -> bytes:
    """Encode an ordered list of (name, value) into an HPACK header block."""
    block = bytearray()
    for name, value in headers:
        block += _encode_header(name.lower(), value)
    return bytes(block)


def _encode_header(name: str, value: str) -> bytes:
    full_index = _STATIC_FULL.get((name, value))
    if full_index is not None:
        return encode_integer(full_index, 7, 0x80)
    name_index = _STATIC_NAMES.get(name, 0)
    field = bytearray(encode_integer(name_index, 4, 0x00))
    if name_index == 0:
        field += _encode_string(name)
    field += _encode_string(value)
    return bytes(field)


def _encode_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return encode_integer(len(raw), 7, 0x00) + raw
