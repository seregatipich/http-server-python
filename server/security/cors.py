"""CORS (Cross-Origin Resource Sharing) utilities for the HTTP server."""

from dataclasses import dataclass
from typing import Optional

from server.domain.http_types import HttpResponse, should_close


@dataclass
class CorsConfig:
    """CORS configuration for cross-origin resource sharing."""

    allowed_origins: list[str]
    allowed_methods: list[str]
    allowed_headers: list[str]
    expose_headers: list[str]
    allow_credentials: bool
    max_age: int


def is_preflight_request(request) -> bool:
    """Check if the request is a CORS preflight OPTIONS request."""
    return (
        request.method == "OPTIONS"
        and "access-control-request-method" in request.headers
    )


def determine_allowed_origin(origin: str, cors_config: CorsConfig) -> Optional[str]:
    """Determine the allowed origin based on CORS configuration."""
    if "*" in cors_config.allowed_origins:
        return origin if cors_config.allow_credentials else "*"
    if origin in cors_config.allowed_origins:
        return origin
    return None


def _apply_preflight_headers(
    headers: dict[str, str], request, cors_config: CorsConfig, allowed_origin: str
) -> None:
    """Apply CORS preflight-specific headers to the response."""
    headers["Access-Control-Allow-Origin"] = allowed_origin
    if allowed_origin != "*":
        headers["Vary"] = "Origin"
    if cors_config.allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"

    headers["Access-Control-Allow-Methods"] = ", ".join(cors_config.allowed_methods)

    requested_headers = request.headers.get("access-control-request-headers", "")
    if requested_headers:
        requested = {h.strip().lower() for h in requested_headers.split(",")}
        allowed = {h.lower() for h in cors_config.allowed_headers}
        if requested.issubset(allowed):
            headers["Access-Control-Allow-Headers"] = requested_headers
        else:
            headers["Access-Control-Allow-Headers"] = ", ".join(
                cors_config.allowed_headers
            )
    else:
        headers["Access-Control-Allow-Headers"] = ", ".join(cors_config.allowed_headers)

    headers["Access-Control-Max-Age"] = str(cors_config.max_age)


def apply_cors_headers(
    headers: dict[str, str],
    request,
    cors_config: Optional[CorsConfig],
) -> None:
    """Apply CORS headers to a response based on the request and configuration."""
    if cors_config is None:
        return

    origin = request.headers.get("origin")
    if not origin:
        return

    allowed_origin = determine_allowed_origin(origin, cors_config)

    if allowed_origin:
        headers["Access-Control-Allow-Origin"] = allowed_origin
        if allowed_origin != "*":
            headers.setdefault("Vary", "Origin")
        if cors_config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        if cors_config.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(
                cors_config.expose_headers
            )


def preflight_response(
    request, cors_config: Optional[CorsConfig], security_headers: dict[str, str]
):
    """Create a 204 response for CORS preflight OPTIONS requests."""
    headers = {**security_headers}

    if cors_config is not None:
        origin = request.headers.get("origin")
        if origin:
            allowed_origin = determine_allowed_origin(origin, cors_config)
            if allowed_origin:
                _apply_preflight_headers(headers, request, cors_config, allowed_origin)

    return HttpResponse(
        "HTTP/1.1 204 No Content",
        headers,
        b"",
        should_close(request.headers),
    )
