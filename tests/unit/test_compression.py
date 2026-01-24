import gzip

from main import accepts_gzip, compress_if_gzip_supported


def test_accepts_gzip_true_for_simple_header():
    headers = {"accept-encoding": "gzip, deflate"}
    assert accepts_gzip(headers)


def test_accepts_gzip_false_when_quality_zero():
    headers = {"accept-encoding": "gzip; q=0"}
    assert not accepts_gzip(headers)


def test_accepts_gzip_ignores_invalid_quality():
    headers = {"accept-encoding": "gzip; q=oops"}
    assert not accepts_gzip(headers)


def test_compress_if_gzip_supported_returns_payload_and_header():
    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(
        payload,
        {"accept-encoding": "gzip"},
    )
    assert gzip.decompress(compressed) == payload
    assert response_headers == {"Content-Encoding": "gzip"}


def test_compress_if_gzip_supported_passthrough_when_not_supported():
    payload = b"hello"
    compressed, response_headers = compress_if_gzip_supported(payload, {})
    assert compressed == payload
    assert response_headers == {}
