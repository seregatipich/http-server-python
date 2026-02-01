"""HTTP response builders for the server."""

import gzip
from pathlib import Path
from typing import Iterator, Optional, Tuple

from cors import apply_cors_headers
from http_types import HttpRequest, HttpResponse, should_close
from sandbox import ForbiddenPath, resolve_sandbox_path


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


def stream_file(filepath: Path, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file contents in fixed-size chunks for streaming responses."""
    with open(filepath, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


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


def file_response(
    request: HttpRequest,
    directory: str,
    cors_config,
    security_headers: dict[str, str],
    files_endpoint_prefix: str,
    server_logger,
) -> HttpResponse:
    """Serve or write a file based on the HTTP method."""
    # pylint: disable=too-many-arguments, too-many-positional-arguments
    filename = request.path[len(files_endpoint_prefix) :]
    try:
        resolved_path = resolve_sandbox_path(directory, filename)
    except ForbiddenPath:
        server_logger.warning(
            "Forbidden path",
            extra={"path": filename, "method": request.method},
        )
        return forbidden_response(request, cors_config, security_headers)

    if request.method == "GET":
        if resolved_path.exists() and resolved_path.is_file():
            headers = {
                "Content-Type": "application/octet-stream",
                **security_headers,
            }
            apply_cors_headers(headers, request, cors_config)
            server_logger.info(
                "Served file",
                extra={"path": resolved_path.as_posix(), "method": request.method},
            )
            return HttpResponse(
                "HTTP/1.1 200 OK",
                headers,
                b"",
                should_close(request.headers),
                body_iter=stream_file(resolved_path),
                use_chunked=True,
            )
        return not_found_response(request, cors_config, security_headers)
    if request.method == "POST":
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved_path, "wb") as file_handle:
            file_handle.write(request.body)
        server_logger.info(
            "Stored file",
            extra={"path": resolved_path.as_posix(), "method": request.method},
        )
        headers = security_headers.copy()
        apply_cors_headers(headers, request, cors_config)
        return HttpResponse(
            "HTTP/1.1 201 Created",
            headers,
            b"",
            should_close(request.headers),
        )
    if resolved_path.is_dir():
        return forbidden_response(request, cors_config, security_headers)
    server_logger.warning(
        "Unsupported method",
        extra={"path": resolved_path.as_posix(), "method": request.method},
    )
    return method_not_allowed_response(request, cors_config, security_headers, None)


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
