"""Unit tests validating gzip negotiation helpers."""

import gzip
import logging

from main import accepts_gzip, compress_if_gzip_supported


def test_accepts_gzip_true_for_simple_header():
    """Gzip should be accepted when declared in Accept-Encoding."""

    headers = {"accept-encoding": "gzip, deflate"}
    assert accepts_gzip(headers)


def test_accepts_gzip_false_when_quality_zero():
    """Quality zero values must disable gzip responses."""

    headers = {"accept-encoding": "gzip; q=0"}
    assert not accepts_gzip(headers)


def test_accepts_gzip_ignores_invalid_quality():
    """Invalid q parameters should disable gzip for safety."""

    headers = {"accept-encoding": "gzip; q=oops"}
    assert not accepts_gzip(headers)


def test_compress_if_gzip_supported_returns_payload_and_header():
    """Compression utility should gzip payloads when supported."""

    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(
        payload,
        {"accept-encoding": "gzip"},
    )
    assert gzip.decompress(compressed) == payload
    assert response_headers == {"Content-Encoding": "gzip"}


def test_compress_if_gzip_supported_passthrough_when_not_supported():
    """Fallback should return payload unchanged when gzip unsupported."""

    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(payload, {})
    assert compressed == payload
    assert not response_headers


def test_compress_if_gzip_supported_logs_debug(caplog):
    """Compression should emit a debug log when gzip is applied."""

    caplog.set_level(logging.DEBUG, logger="http_server.compression")

    payload = b"payload"
    compress_if_gzip_supported(payload, {"accept-encoding": "gzip"})

    assert any(
        record.message == "Compressed payload" and record.size == len(payload)
        for record in caplog.records
    )
