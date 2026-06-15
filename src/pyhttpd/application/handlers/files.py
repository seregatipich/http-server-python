"""Handlers for static file serving and the sandbox index."""

import logging
import mimetypes
from pathlib import Path
from typing import Callable, Iterator, Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.middleware.cors import apply_cors_headers
from pyhttpd.application.rendering import empty_response
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
    Forbidden,
    ForbiddenPath,
    HttpRequest,
    HttpResponse,
    MethodNotAllowed,
    NotFound,
    resolve_sandbox_path,
    should_close,
)
from pyhttpd.domain.ports import Logger

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]
FILE_ALLOWED_METHODS = ("GET", "POST")


def _is_invalid_file_route(remainder: str) -> bool:
    return (
        not remainder
        or remainder.startswith("../")
        or "/../" in remainder
        or remainder.startswith("..")
    )


def _content_type_for_path(resolved_path: Path) -> str:
    mime_type, _ = mimetypes.guess_type(resolved_path.as_posix())
    return mime_type or "application/octet-stream"


def _stream_file(
    resolved_path: Path, logger: Logger, chunk_size: int = 65536
) -> Iterator[bytes]:
    logger.log(logging.DEBUG, "file_streaming_started", path=resolved_path.as_posix())
    with open(resolved_path, "rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            logger.log(logging.DEBUG, "file_chunk_sent", bytes=len(chunk))
            yield chunk


def _streaming_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
) -> HttpResponse:
    headers = {
        "Content-Type": _content_type_for_path(resolved_path),
        **SECURITY_HEADERS,
    }
    apply_cors_headers(headers, request, cors_config)
    logger.log(
        logging.INFO,
        "file_read_complete",
        path=resolved_path.as_posix(),
        method=request.method,
    )
    return HttpResponse(
        "HTTP/1.1 200 OK",
        headers,
        b"",
        should_close(request.headers),
        body_iter=_stream_file(resolved_path, logger),
        use_chunked=True,
    )


def _get_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
) -> HttpResponse:
    if resolved_path.exists() and resolved_path.is_file():
        logger.log(logging.DEBUG, "file_read_started", path=resolved_path.as_posix())
        return _streaming_file_response(request, resolved_path, logger, cors_config)
    logger.log(
        logging.INFO,
        "file_not_found",
        path=resolved_path.as_posix(),
        method=request.method,
    )
    raise NotFound("file not found")


def _post_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
) -> HttpResponse:
    logger.log(
        logging.DEBUG,
        "file_write_started",
        path=resolved_path.as_posix(),
        bytes=len(request.body),
    )
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    with open(resolved_path, "wb") as file_handle:
        file_handle.write(request.body)
    logger.log(
        logging.INFO,
        "file_write_complete",
        path=resolved_path.as_posix(),
        method=request.method,
        bytes_out=len(request.body),
    )
    headers = SECURITY_HEADERS.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 201 Created",
        headers,
        b"",
        should_close(request.headers),
    )


def _unsupported_file_method(
    request: HttpRequest, resolved_path: Path, logger: Logger
) -> HttpResponse:
    if resolved_path.is_dir():
        raise Forbidden("directory access denied")
    logger.log(
        logging.WARNING,
        "unsupported_method",
        path=resolved_path.as_posix(),
        method=request.method,
    )
    raise MethodNotAllowed(FILE_ALLOWED_METHODS)


def make_files_handler(
    directory: str, logger: Logger, cors_config: Optional[CorsConfig] = None
) -> RouteHandler:
    """Build a handler serving and writing files under the sandbox directory."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        remainder = request.path[len(FILES_ENDPOINT_PREFIX) :]
        if _is_invalid_file_route(remainder):
            logger.log(logging.WARNING, "route_invalid", route=request.path)
            raise Forbidden("invalid file path")
        try:
            resolved_path = resolve_sandbox_path(directory, remainder)
        except ForbiddenPath as exc:
            logger.log(
                logging.WARNING,
                "forbidden_path",
                path=remainder,
                method=request.method,
            )
            raise Forbidden("forbidden path") from exc
        if request.method == "GET":
            return _get_file_response(request, resolved_path, logger, cors_config)
        if request.method == "POST":
            return _post_file_response(request, resolved_path, logger, cors_config)
        return _unsupported_file_method(request, resolved_path, logger)

    return handle


def make_index_handler(
    directory: str,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
    document_name: str = "index.html",
) -> RouteHandler:
    """Build a handler serving the sandbox index document."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        try:
            resolved_path = resolve_sandbox_path(directory, document_name)
        except ForbiddenPath as exc:
            raise Forbidden("index path forbidden") from exc
        if resolved_path.exists() and resolved_path.is_file():
            return _streaming_file_response(request, resolved_path, logger, cors_config)
        return empty_response(request, cors_config, SECURITY_HEADERS)

    return handle
