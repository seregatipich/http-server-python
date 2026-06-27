"""HPACK header compression (RFC 7541)."""

from pyhttpd.domain.http2.hpack.decoder import Decoder
from pyhttpd.domain.http2.hpack.encoder import encode_headers
from pyhttpd.domain.http2.hpack.huffman import huffman_decode, huffman_encode
from pyhttpd.domain.http2.hpack.integer import decode_integer, encode_integer

__all__ = [
    "Decoder",
    "encode_headers",
    "huffman_decode",
    "huffman_encode",
    "decode_integer",
    "encode_integer",
]
