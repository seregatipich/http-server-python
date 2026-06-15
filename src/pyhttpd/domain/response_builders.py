"""Pure HTTP response builders."""

import gzip
from collections.abc import Iterable
from typing import Optional, Tuple

from pyhttpd.domain.config import CorsConfig
from pyhttpd.domain.http import HttpRequest, HttpResponse, should_close


def is_preflight_request(request: HttpRequest) -> bool:
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


def _apply_origin_headers(
    headers: dict[str, str],
    cors_config: CorsConfig,
    allowed_origin: str,
) -> None:
    headers["Access-Control-Allow-Origin"] = allowed_origin
    if allowed_origin != "*":
        headers.setdefault("Vary", "Origin")
    if cors_config.allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"


def _allowed_request_headers(request: HttpRequest, cors_config: CorsConfig) -> str:
    requested_headers = request.headers.get("access-control-request-headers", "")
    if not requested_headers:
        return ", ".join(cors_config.allowed_headers)

    requested = {h.strip().lower() for h in requested_headers.split(",")}
    allowed = {h.lower() for h in cors_config.allowed_headers}
    if requested.issubset(allowed):
        return requested_headers
    return ", ".join(cors_config.allowed_headers)


def _apply_preflight_headers(
    headers: dict[str, str],
    request: HttpRequest,
    cors_config: CorsConfig,
    allowed_origin: str,
) -> None:
    """Apply CORS preflight-specific headers to the response."""
    _apply_origin_headers(headers, cors_config, allowed_origin)
    headers["Access-Control-Allow-Methods"] = ", ".join(cors_config.allowed_methods)
    headers["Access-Control-Allow-Headers"] = _allowed_request_headers(
        request, cors_config
    )
    headers["Access-Control-Max-Age"] = str(cors_config.max_age)


def apply_cors_headers(
    headers: dict[str, str],
    request: HttpRequest,
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
        _apply_origin_headers(headers, cors_config, allowed_origin)
        if cors_config.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(
                cors_config.expose_headers
            )


def preflight_response(
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
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


def _gzip_quality(params: str) -> float:
    if not params:
        return 1.0
    for param in params.split(";"):
        key, _, raw_value = param.strip().partition("=")
        if key.lower() != "q" or not raw_value:
            continue
        try:
            return float(raw_value)
        except ValueError:
            return 0.0
    return 1.0


def _is_accepted_gzip_token(token: str) -> bool:
    value = token.strip()
    if not value:
        return False
    algorithm, _, params = value.partition(";")
    return algorithm.strip().lower() == "gzip" and _gzip_quality(params) > 0


def accepts_gzip(headers: dict[str, str]) -> bool:
    """Return True when the Accept-Encoding header includes gzip with q>0."""
    encodings = headers.get("accept-encoding", "")
    return any(_is_accepted_gzip_token(token) for token in encodings.split(","))


def compress_if_gzip_supported(
    payload: bytes, headers: dict[str, str], compression_logger
) -> Tuple[bytes, dict[str, str]]:
    """Compress the payload when the request advertises gzip support."""
    if not accepts_gzip(headers):
        return payload, {}
    compression_logger.debug("Compressed payload", extra={"size": len(payload)})
    return gzip.compress(payload), {"Content-Encoding": "gzip"}


def _response_headers(
    security_headers: dict[str, str],
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    if extra_headers is None:
        return security_headers.copy()
    return {**extra_headers, **security_headers}


def _request_close_preference(request: Optional[HttpRequest]) -> bool:
    if request is None:
        return True
    return should_close(request.headers)


def _basic_response(
    status_line: str,
    security_headers: dict[str, str],
    body: bytes = b"",
    extra_headers: Optional[dict[str, str]] = None,
    close_connection: bool = True,
) -> HttpResponse:
    return HttpResponse(
        status_line,
        _response_headers(security_headers, extra_headers),
        body,
        close_connection,
    )


def _request_response(
    status_line: str,
    request: Optional[HttpRequest],
    cors_config,
    security_headers: dict[str, str],
    body: bytes = b"",
    extra_headers: Optional[dict[str, str]] = None,
    close_connection: Optional[bool] = None,
) -> HttpResponse:
    headers = _response_headers(security_headers, extra_headers)
    if request is not None:
        apply_cors_headers(headers, request, cors_config)
    close = (
        _request_close_preference(request)
        if close_connection is None
        else close_connection
    )
    return HttpResponse(status_line, headers, body, close)


def empty_response(
    request: HttpRequest, cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Return a 200 OK response with no body."""
    return _request_response("HTTP/1.1 200 OK", request, cors_config, security_headers)


def text_response(
    message: str,
    request: HttpRequest,
    cors_config,
    security_headers: dict[str, str],
    compression_logger,
) -> HttpResponse:
    """Return a text/plain response, compressing when appropriate."""
    payload = message.encode()
    payload, headers = compress_if_gzip_supported(
        payload, request.headers, compression_logger
    )
    return _request_response(
        "HTTP/1.1 200 OK",
        request,
        cors_config,
        security_headers,
        payload,
        {"Content-Type": "text/plain", **headers},
    )


def not_found_response(
    request: HttpRequest, cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Return a 404 response reusing the connection preference."""
    return _request_response(
        "HTTP/1.1 404 Not Found",
        request,
        cors_config,
        security_headers,
    )


def forbidden_response(
    request: Optional[HttpRequest], cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 403 response honoring the caller's connection preference."""
    return _request_response(
        "HTTP/1.1 403 Forbidden",
        request,
        cors_config,
        security_headers,
    )


def bad_request_response(
    request: Optional[HttpRequest], cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 400 response honoring the caller's connection preference."""
    return _request_response(
        "HTTP/1.1 400 Bad Request",
        request,
        cors_config,
        security_headers,
    )


def entity_too_large_response(security_headers: dict[str, str]) -> HttpResponse:
    """Produce a 413 response that always closes the connection."""
    return _basic_response("HTTP/1.1 413 Payload Too Large", security_headers)


def rate_limited_response(
    decision, request: HttpRequest, security_headers: dict[str, str]
) -> HttpResponse:
    """Create a 429 response populated with RateLimit headers."""
    retry_after = max(1, int(decision.reset_seconds)) if decision.reset_seconds else 1
    body = b"Rate limit exceeded"
    return _basic_response(
        "HTTP/1.1 429 Too Many Requests",
        security_headers,
        body,
        {"Retry-After": str(retry_after), **decision.headers},
        should_close(request.headers),
    )


def connection_limited_response(
    limit_type: str | None, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 503 response describing which connection quota was exceeded."""
    reason = "Connection limit exceeded"
    if limit_type:
        reason = f"{limit_type} connection limit exceeded"
    return _basic_response(
        "HTTP/1.1 503 Service Unavailable",
        security_headers,
        reason.encode(),
        {"Retry-After": "1"},
    )


def draining_response(security_headers: dict[str, str]) -> HttpResponse:
    """Produce a 503 response indicating the server is draining."""
    return _basic_response(
        "HTTP/1.1 503 Service Unavailable",
        security_headers,
        b"draining",
        {"Connection": "close"},
    )


def healthz_response(
    is_draining: bool, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a health check response based on server state."""
    if is_draining:
        return draining_response(security_headers)
    return _basic_response(
        "HTTP/1.1 200 OK",
        security_headers,
        close_connection=False,
    )


def method_not_allowed_response(
    request: HttpRequest,
    cors_config,
    security_headers: dict[str, str],
    allowed_methods: Iterable[str],
) -> HttpResponse:
    """Produce a 405 response enumerating the supported HTTP methods."""
    allow_header = ", ".join(sorted(allowed_methods))
    return _request_response(
        "HTTP/1.1 405 Method Not Allowed",
        request,
        cors_config,
        security_headers,
        extra_headers={"Allow": allow_header},
    )
