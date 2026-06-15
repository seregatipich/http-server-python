"""File serving handlers."""

import logging
import mimetypes
from pathlib import Path
from typing import Iterator

from pyhttpd.adapters.logging.correlation_adapter import CorrelationLoggerAdapter
from pyhttpd.domain import (
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    apply_cors_headers,
    empty_response,
    forbidden_response,
    method_not_allowed_response,
    not_found_response,
    resolve_sandbox_path,
    should_close,
)

FILE_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.handlers.file"), {}
)
FILE_ALLOWED_METHODS = ("GET", "POST")


def stream_file(filepath: Path, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield file contents in fixed-size chunks for streaming responses."""
    if FILE_LOGGER.logger.isEnabledFor(logging.DEBUG):
        FILE_LOGGER.debug(
            "File streaming started",
            extra={"event": "file_streaming_started", "path": filepath.as_posix()},
        )
    with open(filepath, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            if FILE_LOGGER.logger.isEnabledFor(logging.DEBUG):
                FILE_LOGGER.debug(
                    "File chunk sent",
                    extra={"event": "file_chunk_sent", "bytes": len(chunk)},
                )
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
        "File read operation complete",
        extra={
            "event": "file_read_complete",
            "path": resolved_path.as_posix(),
            "method": request.method,
        },
    )
    return HttpResponse(
        "HTTP/1.1 200 OK",
        headers,
        b"",
        should_close(request.headers),
        body_iter=stream_file(resolved_path),
        use_chunked=True,
    )


def _get_file_response(
    request: HttpRequest,
    resolved_path: Path,
    cors_config,
    security_headers: dict[str, str],
) -> HttpResponse:
    if resolved_path.exists() and resolved_path.is_file():
        if FILE_LOGGER.logger.isEnabledFor(logging.DEBUG):
            FILE_LOGGER.debug(
                "File read started",
                extra={
                    "event": "file_read_started",
                    "path": resolved_path.as_posix(),
                },
            )
        return _streaming_file_response(
            request, resolved_path, cors_config, security_headers
        )
    FILE_LOGGER.info(
        "File not found",
        extra={
            "event": "file_not_found",
            "path": resolved_path.as_posix(),
            "method": request.method,
        },
    )
    return not_found_response(request, cors_config, security_headers)


def _post_file_response(
    request: HttpRequest,
    resolved_path: Path,
    cors_config,
    security_headers: dict[str, str],
) -> HttpResponse:
    if FILE_LOGGER.logger.isEnabledFor(logging.DEBUG):
        FILE_LOGGER.debug(
            "File write started",
            extra={
                "event": "file_write_started",
                "path": resolved_path.as_posix(),
                "bytes": len(request.body),
            },
        )
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    with open(resolved_path, "wb") as file_handle:
        file_handle.write(request.body)
    FILE_LOGGER.info(
        "File write complete",
        extra={
            "event": "file_write_complete",
            "path": resolved_path.as_posix(),
            "method": request.method,
            "bytes_out": len(request.body),
        },
    )
    headers = security_headers.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 201 Created",
        headers,
        b"",
        should_close(request.headers),
    )


def _unsupported_file_method_response(
    request: HttpRequest,
    resolved_path: Path,
    cors_config,
    security_headers: dict[str, str],
) -> HttpResponse:
    if resolved_path.is_dir():
        return forbidden_response(request, cors_config, security_headers)
    FILE_LOGGER.warning(
        "Unsupported method",
        extra={"path": resolved_path.as_posix(), "method": request.method},
    )
    return method_not_allowed_response(
        request, cors_config, security_headers, FILE_ALLOWED_METHODS
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
            "Forbidden path access blocked",
            extra={
                "event": "forbidden_path",
                "path": filename,
                "method": request.method,
            },
        )
        return forbidden_response(request, cors_config, security_headers)

    if request.method == "GET":
        return _get_file_response(request, resolved_path, cors_config, security_headers)
    if request.method == "POST":
        return _post_file_response(
            request, resolved_path, cors_config, security_headers
        )
    return _unsupported_file_method_response(
        request, resolved_path, cors_config, security_headers
    )


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
