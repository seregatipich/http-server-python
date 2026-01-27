"""Unit tests covering request validation and sandbox resolution."""

import pytest

from main import (
    ALLOWED_METHODS,
    MAX_BODY_BYTES,
    ForbiddenPath,
    HttpRequest,
    entity_too_large_response,
    resolve_sandbox_path,
    validate_request,
)


def make_request(
    path: str,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes = b"",
) -> HttpRequest:
    """Construct a HttpRequest test double with sane defaults."""
    return HttpRequest(method, path, headers or {}, body)


def test_validate_request_allows_whitelisted_methods():
    """Allow GET on the root path."""
    request = make_request("/")
    assert validate_request(request) is None


def test_validate_request_rejects_unknown_method():
    """Reject methods outside the allowlist."""
    request = make_request("/", method="DELETE")
    response = validate_request(request)
    assert response is not None
    assert response.status_line == "HTTP/1.1 405 Method Not Allowed"
    allow_header = response.headers.get("Allow", "")
    for method in ALLOWED_METHODS:
        assert method in allow_header


def test_validate_request_requires_content_length_for_post():
    """Reject POST requests missing a Content-Length header."""
    request = make_request("/files/name", method="POST", headers={}, body=b"data")
    response = validate_request(request)
    assert response is not None
    assert response.status_line == "HTTP/1.1 400 Bad Request"


def test_validate_request_rejects_length_mismatch():
    """Reject POST requests where body bytes differ from Content-Length."""
    request = make_request(
        "/files/name",
        method="POST",
        headers={"content-length": "4"},
        body=b"x",
    )
    response = validate_request(request)
    assert response is not None
    assert response.status_line == "HTTP/1.1 400 Bad Request"


def test_validate_request_rejects_oversized_body():
    """Reject POST payloads larger than the configured maximum."""
    payload = b"a" * (MAX_BODY_BYTES + 1)
    request = make_request(
        "/files/name",
        method="POST",
        headers={"content-length": str(len(payload))},
        body=payload,
    )
    response = validate_request(request)
    assert response is not None
    assert response.status_line == entity_too_large_response().status_line


def test_resolve_sandbox_path_accepts_nested_file(tmp_path):
    """Allow resolving nested paths in the sandbox."""
    resolved = resolve_sandbox_path(tmp_path.as_posix(), "nested/file.txt")
    assert resolved == (tmp_path / "nested" / "file.txt").resolve()


def test_resolve_sandbox_path_blocks_traversal(tmp_path):
    """Block traversal attempts via parent directory references."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(tmp_path.as_posix(), "../etc/passwd")


def test_resolve_sandbox_path_blocks_null_bytes(tmp_path):
    """Block paths containing null bytes."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(tmp_path.as_posix(), "name\x00.txt")


def test_resolve_sandbox_path_blocks_empty_path(tmp_path):
    """Block empty user-supplied paths."""
    with pytest.raises(ForbiddenPath):
        resolve_sandbox_path(tmp_path.as_posix(), "")
