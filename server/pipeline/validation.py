"""Request validation utilities for HTTP server."""

from server.domain.http_types import HttpRequest
from server.domain.response_builders import (
    bad_request_response,
    entity_too_large_response,
    forbidden_response,
    method_not_allowed_response,
)


class RequestEntityTooLarge(Exception):
    """Raised when a request body exceeds configured limits."""


def enforce_allowed_method(
    request: HttpRequest,
    allowed_methods: set[str],
    cors_config,
    security_headers: dict[str, str],
):
    """Ensure the HTTP method is part of the supported allowlist."""
    if request.method in allowed_methods:
        return None

    return method_not_allowed_response(
        request, cors_config, security_headers, allowed_methods
    )


def enforce_safe_path(
    request: HttpRequest, cors_config, security_headers: dict[str, str]
):
    """Validate that the path conforms to sandbox safety requirements."""
    if not request.path.startswith("/") or "\x00" in request.path:
        return bad_request_response(request, cors_config, security_headers)
    if (
        "/../" in request.path
        or request.path.endswith("/..")
        or request.path.startswith("/..")
    ):
        return forbidden_response(request, cors_config, security_headers)
    return None


def enforce_post_constraints(
    request: HttpRequest,
    max_body_bytes: int,
    cors_config,
    security_headers: dict[str, str],
):
    """Validate POST-specific invariants such as Content-Length and size."""
    declared_length = request.headers.get("content-length")
    if declared_length is None:
        return bad_request_response(request, cors_config, security_headers)
    try:
        content_length = int(declared_length)
    except ValueError:
        return bad_request_response(request, cors_config, security_headers)
    if content_length != len(request.body):
        return bad_request_response(request, cors_config, security_headers)
    if content_length > max_body_bytes:
        return entity_too_large_response(security_headers)
    return None


def validate_request(
    request: HttpRequest,
    allowed_methods: set[str],
    max_body_bytes: int,
    cors_config,
    security_headers: dict[str, str],
):
    """Return an error response when the request fails validation checks."""
    method_error = enforce_allowed_method(
        request, allowed_methods, cors_config, security_headers
    )
    if method_error is not None:
        return method_error

    path_error = enforce_safe_path(request, cors_config, security_headers)
    if path_error is not None:
        return path_error

    if request.method == "POST":
        return enforce_post_constraints(
            request, max_body_bytes, cors_config, security_headers
        )

    return None
