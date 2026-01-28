"""Unit tests validating gzip negotiation helpers."""

import gzip
import logging
from typing import TYPE_CHECKING

from main import accepts_gzip, compress_if_gzip_supported

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture


def test_accepts_gzip_true_for_simple_header() -> None:
    """Gzip should be accepted when declared in Accept-Encoding."""

    headers = {"accept-encoding": "gzip, deflate"}
    assert accepts_gzip(headers)


def test_accepts_gzip_false_when_quality_zero() -> None:
    """Quality zero values must disable gzip responses."""

    headers = {"accept-encoding": "gzip; q=0"}
    assert not accepts_gzip(headers)


def test_accepts_gzip_ignores_invalid_quality() -> None:
    """Invalid q parameters should disable gzip for safety."""

    headers = {"accept-encoding": "gzip; q=oops"}
    assert not accepts_gzip(headers)


def test_compress_if_gzip_supported_returns_payload_and_header() -> None:
    """Compression utility should gzip payloads when supported."""

    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(
        payload,
        {"accept-encoding": "gzip"},
    )
    assert gzip.decompress(compressed) == payload
    assert response_headers == {"Content-Encoding": "gzip"}


def test_compress_if_gzip_supported_passthrough_when_not_supported() -> None:
    """Fallback should return payload unchanged when gzip unsupported."""

    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(payload, {})
    assert compressed == payload
    assert not response_headers


def test_compress_if_gzip_supported_logs_debug(
    caplog: "LogCaptureFixture",
) -> None:
    """Compression should emit a debug log when gzip is applied."""

    caplog.set_level(logging.DEBUG, logger="http_server.compression")

    payload = b"payload"
    compress_if_gzip_supported(payload, {"accept-encoding": "gzip"})

    assert any(
        record.message == "Compressed payload" and record.size == len(payload)
        for record in caplog.records
    )
