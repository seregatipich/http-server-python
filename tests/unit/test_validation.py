"""Unit tests covering request validation and sandbox resolution."""

import pytest

from cors import (
    CorsConfig,
    apply_cors_headers,
    determine_allowed_origin,
    is_preflight_request,
    preflight_response,
)
from main import ALLOWED_METHODS, MAX_BODY_BYTES
from responses import HttpRequest, entity_too_large_response
from sandbox import ForbiddenPath, resolve_sandbox_path
from validation import validate_request

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
}


def make_request(
    path: str,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes = b"",
) -> HttpRequest:
    """Construct a HttpRequest test double with sane defaults."""
    return HttpRequest(method, path, headers or {}, body)


def validate_test_request(request: HttpRequest):
    """Helper to call validate_request with test defaults."""
    return validate_request(
        request, ALLOWED_METHODS, MAX_BODY_BYTES, None, SECURITY_HEADERS
    )


def test_validate_request_allows_whitelisted_methods():
    """Allow GET on the root path."""
    request = make_request("/")
    assert validate_test_request(request) is None


def test_validate_request_rejects_unknown_method():
    """Reject methods outside the allowlist."""
    request = make_request("/", method="DELETE")
    response = validate_test_request(request)
    assert response is not None
    assert response.status_line == "HTTP/1.1 405 Method Not Allowed"
    allow_header = response.headers.get("Allow", "")
    for method in ALLOWED_METHODS:
        assert method in allow_header


def test_validate_request_requires_content_length_for_post():
    """Reject POST requests missing a Content-Length header."""
    request = make_request("/files/name", method="POST", headers={}, body=b"data")
    response = validate_test_request(request)
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
    response = validate_test_request(request)
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
    response = validate_test_request(request)
    assert response is not None
    assert (
        response.status_line == entity_too_large_response(SECURITY_HEADERS).status_line
    )


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


def test_validate_request_allows_options_method():
    """Allow OPTIONS method without POST constraints."""
    request = make_request("/", method="OPTIONS")
    assert validate_test_request(request) is None


def test_validate_request_options_without_content_length():
    """Allow OPTIONS requests without Content-Length header."""
    request = make_request("/files/name", method="OPTIONS", headers={})
    assert validate_test_request(request) is None


def test_is_preflight_request_detects_preflight():
    """Detect CORS preflight OPTIONS requests."""
    request = make_request(
        "/",
        method="OPTIONS",
        headers={"access-control-request-method": "POST"},
    )
    assert is_preflight_request(request) is True


def test_is_preflight_request_rejects_non_preflight():
    """Reject regular OPTIONS requests without preflight headers."""
    request = make_request("/", method="OPTIONS")
    assert is_preflight_request(request) is False


def test_is_preflight_request_rejects_non_options():
    """Reject non-OPTIONS requests even with preflight headers."""
    request = make_request(
        "/",
        method="GET",
        headers={"access-control-request-method": "POST"},
    )
    assert is_preflight_request(request) is False


def test_apply_cors_headers_with_wildcard_origin():
    """Apply wildcard CORS headers when configured."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request("/", headers={"origin": "https://example.com"})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "Vary" not in headers
    assert "Access-Control-Allow-Credentials" not in headers
    assert headers["Access-Control-Expose-Headers"] == "X-Request-ID"


def test_apply_cors_headers_with_specific_origin():
    """Apply specific origin CORS headers when origin is in allowlist."""
    cors_config = CorsConfig(
        allowed_origins=["https://example.com", "https://app.example.com"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request("/", headers={"origin": "https://example.com"})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert headers["Vary"] == "Origin"
    assert headers["Access-Control-Expose-Headers"] == "X-Request-ID"


def test_apply_cors_headers_rejects_unlisted_origin():
    """Do not apply CORS headers when origin is not in allowlist."""
    cors_config = CorsConfig(
        allowed_origins=["https://example.com"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request("/", headers={"origin": "https://evil.com"})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert "Access-Control-Allow-Origin" not in headers


def test_apply_cors_headers_with_credentials():
    """Apply credentials header when configured."""
    cors_config = CorsConfig(
        allowed_origins=["https://example.com"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=True,
        max_age=86400,
    )
    request = make_request("/", headers={"origin": "https://example.com"})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"


def test_apply_cors_headers_credentials_with_wildcard():
    """Use specific origin instead of wildcard when credentials enabled."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=True,
        max_age=86400,
    )
    request = make_request("/", headers={"origin": "https://example.com"})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Vary"] == "Origin"


def test_apply_cors_headers_without_origin():
    """Do not apply CORS headers when no Origin header present."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request("/", headers={})
    headers = {}
    apply_cors_headers(headers, request, cors_config)
    assert "Access-Control-Allow-Origin" not in headers


def test_preflight_response_with_allowed_origin():
    """Return 204 preflight response with CORS headers."""
    cors_config = CorsConfig(
        allowed_origins=["https://example.com"],
        allowed_methods=["GET", "POST", "OPTIONS"],
        allowed_headers=["Content-Type", "Authorization"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request(
        "/",
        method="OPTIONS",
        headers={
            "origin": "https://example.com",
            "access-control-request-method": "POST",
        },
    )
    response = preflight_response(request, cors_config, SECURITY_HEADERS)
    assert response.status_line == "HTTP/1.1 204 No Content"
    assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert response.headers["Access-Control-Allow-Methods"] == "GET, POST, OPTIONS"
    assert (
        response.headers["Access-Control-Allow-Headers"]
        == "Content-Type, Authorization"
    )
    assert response.headers["Access-Control-Max-Age"] == "86400"


def test_preflight_response_with_requested_headers():
    """Echo requested headers when they are in the allowlist."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type", "Authorization", "X-Custom"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request(
        "/",
        method="OPTIONS",
        headers={
            "origin": "https://example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "Content-Type, Authorization",
        },
    )
    response = preflight_response(request, cors_config, SECURITY_HEADERS)
    assert (
        response.headers["Access-Control-Allow-Headers"]
        == "Content-Type, Authorization"
    )


def test_preflight_response_with_forbidden_headers():
    """Return allowed headers when requested headers not in allowlist."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["GET", "POST"],
        allowed_headers=["Content-Type"],
        expose_headers=["X-Request-ID"],
        allow_credentials=False,
        max_age=86400,
    )
    request = make_request(
        "/",
        method="OPTIONS",
        headers={
            "origin": "https://example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "Content-Type, X-Forbidden",
        },
    )
    response = preflight_response(request, cors_config, SECURITY_HEADERS)
    assert response.headers["Access-Control-Allow-Headers"] == "Content-Type"


def test_determine_allowed_origin_mixed_policies():
    """Select specific origin from mixed allowlist (wildcard + explicit)."""
    cors_config = CorsConfig(
        allowed_origins=["*", "https://specific.com"],
        allowed_methods=["GET"],
        allowed_headers=[],
        expose_headers=[],
        allow_credentials=True,
        max_age=86400,
    )
    assert (
        determine_allowed_origin("https://specific.com", cors_config)
        == "https://specific.com"
    )
    assert (
        determine_allowed_origin("https://random.com", cors_config)
        == "https://random.com"
    )


def test_validate_request_oversized_post_with_origin():
    """Ensure 413 response includes CORS headers when Origin is present."""
    cors_config = CorsConfig(
        allowed_origins=["*"],
        allowed_methods=["POST"],
        allowed_headers=[],
        expose_headers=[],
        allow_credentials=False,
        max_age=86400,
    )
    payload = b"a" * (MAX_BODY_BYTES + 1)
    request = make_request(
        "/files/large",
        method="POST",
        headers={"content-length": str(len(payload)), "origin": "https://example.com"},
        body=payload,
    )

    response = validate_request(
        request, ALLOWED_METHODS, MAX_BODY_BYTES, cors_config, SECURITY_HEADERS
    )
    assert response is not None
    assert response.status_line == "HTTP/1.1 413 Payload Too Large"
    assert "Access-Control-Allow-Origin" not in response.headers


def test_options_request_missing_preflight_header_returns_none():
    """Treat OPTIONS without Access-Control-Request-Method as standard request (pass validation)."""
    request = make_request(
        "/", method="OPTIONS", headers={"origin": "https://example.com"}
    )
    assert validate_test_request(request) is None
