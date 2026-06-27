"""HPACK header block decoder (RFC 7541 section 6)."""

from typing import List, Tuple

from pyhttpd.domain.http2.hpack.dynamic_table import DynamicTable
from pyhttpd.domain.http2.hpack.huffman import huffman_decode
from pyhttpd.domain.http2.hpack.integer import decode_integer
from pyhttpd.domain.http2.hpack.static_table import STATIC_TABLE, STATIC_TABLE_SIZE

Header = Tuple[str, str]


class Decoder:
    """Stateful HPACK decoder holding the dynamic table across header blocks."""

    def __init__(self, max_dynamic_size: int = 4096) -> None:
        self._dynamic = DynamicTable(max_dynamic_size)

    def decode(self, block: bytes) -> List[Header]:
        """Decode one header block into an ordered list of (name, value)."""
        headers: List[Header] = []
        offset = 0
        while offset < len(block):
            first = block[offset]
            if first & 0x80:
                offset = self._indexed(block, offset, headers)
            elif first & 0x40:
                offset = self._literal(block, offset, 6, headers, index=True)
            elif first & 0x20:
                size, offset = decode_integer(block, offset, 5)
                self._dynamic.resize(size)
            else:
                offset = self._literal(block, offset, 4, headers, index=False)
        return headers

    def _indexed(self, block: bytes, offset: int, headers: List[Header]) -> int:
        index, offset = decode_integer(block, offset, 7)
        headers.append(self._lookup(index))
        return offset

    def _literal(
        self,
        block: bytes,
        offset: int,
        name_prefix: int,
        headers: List[Header],
        index: bool,
    ) -> int:
        name_index, offset = decode_integer(block, offset, name_prefix)
        if name_index == 0:
            name, offset = self._read_string(block, offset)
        else:
            name = self._lookup(name_index)[0]
        value, offset = self._read_string(block, offset)
        if index:
            self._dynamic.add(name, value)
        headers.append((name, value))
        return offset

    def _read_string(self, block: bytes, offset: int) -> Tuple[str, int]:
        is_huffman = bool(block[offset] & 0x80)
        length, offset = decode_integer(block, offset, 7)
        raw = block[offset : offset + length]
        offset += length
        decoded = huffman_decode(raw) if is_huffman else raw
        return decoded.decode("utf-8"), offset

    def _lookup(self, index: int) -> Header:
        if 1 <= index <= STATIC_TABLE_SIZE:
            return STATIC_TABLE[index - 1]
        return self._dynamic.get(index - STATIC_TABLE_SIZE - 1)
