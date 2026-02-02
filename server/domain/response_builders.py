"""Pure HTTP response builders."""

import gzip
from typing import Optional, Tuple

from server.security.cors import apply_cors_headers
from server.domain.http_types import HttpRequest, HttpResponse, should_close


def accepts_gzip(headers: dict[str, str]) -> bool:
    """Return True when the Accept-Encoding header includes gzip with q>0."""
    encodings = headers.get("accept-encoding", "")
    for token in encodings.split(","):
        value = token.strip()
        if not value:
            continue
        algorithm, _, params = value.partition(";")
        if algorithm.strip().lower() != "gzip":
            continue
        quality = 1.0
        if params:
            for param in params.split(";"):
                key, _, raw_value = param.strip().partition("=")
                if key.lower() == "q" and raw_value:
                    try:
                        quality = float(raw_value)
                    except ValueError:
                        quality = 0.0
                    break
        if quality > 0:
            return True
    return False


def compress_if_gzip_supported(
    payload: bytes, headers: dict[str, str], compression_logger
) -> Tuple[bytes, dict[str, str]]:
    """Compress the payload when the request advertises gzip support."""
    if not accepts_gzip(headers):
        return payload, {}
    compression_logger.debug("Compressed payload", extra={"size": len(payload)})
    return gzip.compress(payload), {"Content-Encoding": "gzip"}


def empty_response(
    request: HttpRequest, cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Return a 200 OK response with no body."""
    headers = security_headers.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse("HTTP/1.1 200 OK", headers, b"", should_close(request.headers))


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
    base_headers = {"Content-Type": "text/plain", **headers, **security_headers}
    apply_cors_headers(base_headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 200 OK", base_headers, payload, should_close(request.headers)
    )


def not_found_response(
    request: HttpRequest, cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Return a 404 response reusing the connection preference."""
    headers = security_headers.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 404 Not Found",
        headers,
        b"",
        should_close(request.headers),
    )


def forbidden_response(
    request: Optional[HttpRequest], cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 403 response honoring the caller's connection preference."""
    req_headers = request.headers if request is not None else {}
    headers = security_headers.copy()
    if request is not None:
        apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 403 Forbidden",
        headers,
        b"",
        should_close(req_headers) if request is not None else True,
    )


def bad_request_response(
    request: Optional[HttpRequest], cors_config, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 400 response honoring the caller's connection preference."""
    req_headers = request.headers if request is not None else {}
    headers = security_headers.copy()
    if request is not None:
        apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 400 Bad Request",
        headers,
        b"",
        should_close(req_headers) if request is not None else True,
    )


def entity_too_large_response(security_headers: dict[str, str]) -> HttpResponse:
    """Produce a 413 response that always closes the connection."""
    return HttpResponse(
        "HTTP/1.1 413 Payload Too Large", security_headers.copy(), b"", True
    )


def rate_limited_response(
    decision, request: HttpRequest, security_headers: dict[str, str]
) -> HttpResponse:
    """Create a 429 response populated with RateLimit headers."""
    retry_after = max(1, int(decision.reset_seconds)) if decision.reset_seconds else 1
    headers = {"Retry-After": str(retry_after), **decision.headers, **security_headers}
    body = b"Rate limit exceeded"
    return HttpResponse(
        "HTTP/1.1 429 Too Many Requests",
        headers,
        body,
        should_close(request.headers),
    )


def connection_limited_response(
    limit_type: str | None, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 503 response describing which connection quota was exceeded."""
    reason = "Connection limit exceeded"
    if limit_type:
        reason = f"{limit_type} connection limit exceeded"
    headers = {"Retry-After": "1", **security_headers}
    return HttpResponse(
        "HTTP/1.1 503 Service Unavailable",
        headers,
        reason.encode(),
        True,
    )


def draining_response(security_headers: dict[str, str]) -> HttpResponse:
    """Produce a 503 response indicating the server is draining."""
    headers = {"Connection": "close", **security_headers}
    return HttpResponse(
        "HTTP/1.1 503 Service Unavailable",
        headers,
        b"draining",
        True,
    )


def healthz_response(
    is_draining: bool, security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a health check response based on server state."""
    if is_draining:
        headers = {"Connection": "close", **security_headers}
        return HttpResponse(
            "HTTP/1.1 503 Service Unavailable",
            headers,
            b"draining",
            True,
        )
    return HttpResponse(
        "HTTP/1.1 200 OK",
        security_headers.copy(),
        b"",
        False,
    )


def method_not_allowed_response(
    request: HttpRequest, cors_config, security_headers: dict[str, str], allowed_methods
) -> HttpResponse:
    """Produce a 405 response enumerating the supported HTTP methods."""
    allow_header = ", ".join(sorted(allowed_methods))
    headers = {"Allow": allow_header, **security_headers}
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 405 Method Not Allowed",
        headers,
        b"",
        should_close(request.headers),
    )
