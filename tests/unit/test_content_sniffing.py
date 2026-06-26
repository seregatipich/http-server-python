"""Unit tests for magic-byte content-type sniffing."""

import pytest

from pyhttpd.domain import sniff_content_type


@pytest.mark.parametrize(
    "head, expected",
    [
        (b"\x89PNG\r\n\x1a\n....", "image/png"),
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"GIF89a", "image/gif"),
        (b"GIF87a", "image/gif"),
        (b"%PDF-1.7", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b\x08", "application/gzip"),
        (b"<!DOCTYPE html>", "text/html"),
        (b"<html>", "text/html"),
        (b'{"key": 1}', "application/json"),
    ],
)
def test_known_signatures(head, expected):
    """Recognized magic bytes map to their content type."""
    assert sniff_content_type(head) == expected


def test_unknown_signature_returns_none():
    """Unrecognized bytes return None so callers can fall back."""
    assert sniff_content_type(b"\x00\x01\x02nonsense") is None


def test_empty_input_returns_none():
    """Empty input yields no guess."""
    assert sniff_content_type(b"") is None
