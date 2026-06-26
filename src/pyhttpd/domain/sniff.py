"""Magic-byte content-type sniffing using a small stdlib signature table."""

from typing import Optional

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<!doctype html", "text/html"),
    (b"<html", "text/html"),
)


def sniff_content_type(head: bytes) -> Optional[str]:
    """Return a content type guessed from leading bytes, or None."""
    if not head:
        return None
    for signature, content_type in _SIGNATURES:
        if head.startswith(signature):
            return content_type
    stripped = head.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "application/json"
    return None
