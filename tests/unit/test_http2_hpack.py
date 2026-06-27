"""Unit tests for HPACK against RFC 7541 golden vectors (F13)."""

import pytest

from pyhttpd.domain.http2.hpack import Decoder, encode_headers
from pyhttpd.domain.http2.hpack.huffman import huffman_decode, huffman_encode
from pyhttpd.domain.http2.hpack.integer import decode_integer, encode_integer


def test_integer_encode_rfc_c11() -> None:
    # RFC 7541 C.1.1: 10 with a 5-bit prefix.
    assert encode_integer(10, 5) == bytes([10])
    # RFC 7541 C.1.2: 1337 with a 5-bit prefix -> 31, 154, 10.
    assert encode_integer(1337, 5) == bytes([31, 154, 10])


def test_integer_round_trip() -> None:
    for value in (0, 30, 31, 127, 128, 1337, 100000):
        encoded = encode_integer(value, 5)
        decoded, offset = decode_integer(encoded, 0, 5)
        assert decoded == value
        assert offset == len(encoded)


def test_huffman_decodes_rfc_c41_authority() -> None:
    # RFC 7541 C.4.1: "www.example.com" Huffman-encoded.
    encoded = bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")
    assert huffman_decode(encoded) == b"www.example.com"


def test_huffman_decodes_rfc_c61_values() -> None:
    # RFC 7541 C.6.1: "302", "private", and a date string, Huffman-encoded.
    assert huffman_decode(bytes.fromhex("6402")) == b"302"
    assert huffman_decode(bytes.fromhex("aec3771a4b")) == b"private"
    assert (
        huffman_decode(bytes.fromhex("d07abe941054d444a8200595040b8166e082a62d1bff"))
        == b"Mon, 21 Oct 2013 20:13:21 GMT"
    )


def test_huffman_round_trip_printable() -> None:
    for text in (b"/sample/path", b"custom-key", b"gzip", b"www.example.com"):
        assert huffman_decode(huffman_encode(text)) == text


def test_decoder_rfc_c31_first_request() -> None:
    # RFC 7541 C.3.1: literal headers without Huffman.
    block = bytes.fromhex("828684410f7777772e6578616d706c652e636f6d")
    headers = Decoder().decode(block)
    assert headers == [
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ]


def test_decoder_rfc_c41_huffman_request() -> None:
    # RFC 7541 C.4.1: same request with Huffman-coded authority.
    block = bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")
    headers = Decoder().decode(block)
    assert headers == [
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ]


def test_encoder_round_trips_through_decoder() -> None:
    headers = [
        (":status", "200"),
        ("content-type", "text/plain"),
        ("content-length", "5"),
        ("x-custom", "value"),
    ]
    block = encode_headers(headers)
    assert Decoder().decode(block) == headers


def test_encoder_uses_static_index_for_known_status() -> None:
    # ":status 200" is static index 8 -> single indexed byte 0x88.
    assert encode_headers([(":status", "200")]) == bytes([0x88])


def test_huffman_rejects_eos_in_stream() -> None:
    with pytest.raises(ValueError):
        huffman_decode(bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
