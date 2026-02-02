"""File serving handlers."""

import logging
import mimetypes
from pathlib import Path
from typing import Iterator

from server.domain.correlation_id import CorrelationLoggerAdapter
from server.domain.http_types import HttpRequest, HttpResponse, should_close
from server.domain.response_builders import (
    empty_response,
    forbidden_response,
    method_not_allowed_response,
    not_found_response,
)
from server.domain.sandbox import ForbiddenPath, resolve_sandbox_path
from server.security.cors import apply_cors_headers

FILE_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.files"), {})


def stream_file(filepath: Path, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file contents in fixed-size chunks for streaming responses."""
    with open(filepath, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _content_type_for_path(filepath: Path) -> str:
    mime_type, _ = mimetypes.guess_type(filepath.as_posix())
    return mime_type or "application/octet-stream"


def _streaming_file_response(
    request: HttpRequest,
    resolved_path: Path,
    cors_config,
    security_headers: dict[str, str],
) -> HttpResponse:
    headers = {
        "Content-Type": _content_type_for_path(resolved_path),
        **security_headers,
    }
    apply_cors_headers(headers, request, cors_config)
    FILE_LOGGER.info(
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


def file_response(
    request: HttpRequest,
    directory: str,
    cors_config,
    security_headers: dict[str, str],
    files_endpoint_prefix: str,
) -> HttpResponse:
    """Serve or write a file based on the HTTP method."""
    # pylint: disable=too-many-arguments, too-many-positional-arguments
    filename = request.path[len(files_endpoint_prefix) :]
    try:
        resolved_path = resolve_sandbox_path(directory, filename)
    except ForbiddenPath:
        FILE_LOGGER.warning(
            "Forbidden path",
            extra={"path": filename, "method": request.method},
        )
        return forbidden_response(request, cors_config, security_headers)

    if request.method == "GET":
        if resolved_path.exists() and resolved_path.is_file():
            return _streaming_file_response(
                request, resolved_path, cors_config, security_headers
            )
        return not_found_response(request, cors_config, security_headers)
    if request.method == "POST":
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        with open(resolved_path, "wb") as file_handle:
            file_handle.write(request.body)
        FILE_LOGGER.info(
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
    FILE_LOGGER.warning(
        "Unsupported method",
        extra={"path": resolved_path.as_posix(), "method": request.method},
    )
    return method_not_allowed_response(request, cors_config, security_headers, None)


def index_response(
    request: HttpRequest,
    directory: str,
    cors_config,
    security_headers: dict[str, str],
    document_name: str = "index.html",
) -> HttpResponse:
    """Serve the sandbox index document or return an empty response."""
    # pylint: disable=too-many-arguments
    try:
        resolved_path = resolve_sandbox_path(directory, document_name)
    except ForbiddenPath:
        return empty_response(request, cors_config, security_headers)
    if resolved_path.exists() and resolved_path.is_file():
        return _streaming_file_response(
            request, resolved_path, cors_config, security_headers
        )
    return empty_response(request, cors_config, security_headers)
