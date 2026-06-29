"""Handlers for static file serving and the sandbox index."""

import errno
import logging
import mimetypes
import os
import tempfile
import zlib
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.cors_headers import apply_cors_headers
from pyhttpd.application.handlers.autoindex import render_autoindex
from pyhttpd.application.rendering import accepts_gzip, empty_response
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    BadRequest,
    ByteRange,
    CorsConfig,
    FileServingOptions,
    Forbidden,
    ForbiddenPath,
    HttpError,
    HttpRequest,
    HttpResponse,
    Logger,
    MethodNotAllowed,
    NotFound,
    RangeNotSatisfiable,
    compute_etag,
    http_date,
    is_not_modified,
    parse_http_date,
    parse_range,
    resolve_sandbox_path,
    should_close,
    sniff_content_type,
)

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]
FILE_ALLOWED_METHODS = ("DELETE", "GET", "HEAD", "POST", "PUT")
_DEFAULT_OPTIONS = FileServingOptions()


def _is_invalid_file_route(remainder: str) -> bool:
    # An empty remainder is the sandbox root, served by autoindex (or 404), not
    # an invalid route; traversal attempts remain rejected.
    return (
        remainder.startswith("../") or "/../" in remainder or remainder.startswith("..")
    )


def _client_error_for(error: OSError) -> Optional[HttpError]:
    """Map a client-caused filesystem error to a 4xx, or None for a server fault."""
    if isinstance(error, IsADirectoryError):
        return Forbidden("directory access denied")
    if isinstance(error, (NotADirectoryError, FileExistsError)):
        return BadRequest("invalid file path")
    if error.errno == errno.ENAMETOOLONG:
        return BadRequest("path too long")
    return None


def _if_range_satisfied(
    request_headers: dict[str, str], etag: str, mtime_epoch: float
) -> bool:
    """Return whether an If-Range precondition permits serving a partial response."""
    if_range = request_headers.get("if-range", "").strip()
    if not if_range:
        return True
    if if_range.startswith('"') or if_range.startswith("W/"):
        return if_range == etag
    parsed = parse_http_date(if_range)
    return parsed is not None and int(mtime_epoch) <= int(parsed)


def _content_type_for_path(
    resolved_path: Path, options: FileServingOptions = _DEFAULT_OPTIONS
) -> str:
    mime_type, _ = mimetypes.guess_type(resolved_path.as_posix())
    if mime_type:
        return mime_type
    if options.content_sniffing:
        with open(resolved_path, "rb") as file_handle:
            sniffed = sniff_content_type(file_handle.read(256))
        if sniffed:
            return sniffed
    return "application/octet-stream"


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


def _stream_handle(
    file_handle: BinaryIO, size: int, logger: Logger, chunk_size: int = 65536
) -> Iterator[bytes]:
    """Stream exactly ``size`` bytes from an already-open handle, then close it.

    The handle is opened once at request time and its size taken from the same
    descriptor, so the declared Content-Length always matches the bytes served
    even if the path is atomically replaced concurrently (the descriptor keeps
    the original inode).
    """
    logger.log(logging.DEBUG, "file_streaming_started")
    remaining = size
    try:
        while remaining > 0:
            chunk = file_handle.read(min(chunk_size, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            logger.log(logging.DEBUG, "file_chunk_sent", bytes=len(chunk))
            yield chunk
    finally:
        file_handle.close()


def _stream_range_handle(
    file_handle: BinaryIO, byte_range: ByteRange, chunk_size: int = 65536
) -> Iterator[bytes]:
    remaining = byte_range.length
    try:
        file_handle.seek(byte_range.start)
        while remaining > 0:
            chunk = file_handle.read(min(chunk_size, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk
    finally:
        file_handle.close()


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
    return HttpResponse(
        "HTTP/1.1 200 OK",
        headers,
        b"",
        should_close(request.headers),
        body_iter=_stream_file(resolved_path, logger),
        use_chunked=True,
    )


def _gzip_eligible(content_type: str, size: int, options: FileServingOptions) -> bool:
    if not options.gzip or size < options.gzip_min_bytes:
        return False
    return any(content_type.startswith(prefix) for prefix in options.gzip_types)


def _base_file_headers(
    request: HttpRequest,
    content_type: str,
    etag: str,
    mtime_epoch: float,
    cors_config: Optional[CorsConfig],
    options: FileServingOptions,
) -> dict[str, str]:
    headers = {
        "Content-Type": content_type,
        "ETag": etag,
        "Last-Modified": http_date(mtime_epoch),
        "Accept-Ranges": "bytes",
        "Vary": "Accept-Encoding",
        **SECURITY_HEADERS,
    }
    if options.cache_control:
        headers["Cache-Control"] = options.cache_control
    apply_cors_headers(headers, request, cors_config)
    return headers


def _not_modified_response(
    request: HttpRequest, headers: dict[str, str]
) -> HttpResponse:
    headers = {
        key: value
        for key, value in headers.items()
        if key in {"ETag", "Last-Modified", "Cache-Control", "Vary", *SECURITY_HEADERS}
    }
    return HttpResponse(
        "HTTP/1.1 304 Not Modified",
        headers,
        b"",
        should_close(request.headers),
        content_length=0,
    )


def _range_response(
    request: HttpRequest,
    file_handle: BinaryIO,
    byte_range: ByteRange,
    headers: dict[str, str],
    file_size: int,
) -> HttpResponse:
    headers = dict(headers)
    headers["Content-Range"] = f"bytes {byte_range.start}-{byte_range.end}/{file_size}"
    return HttpResponse(
        "HTTP/1.1 206 Partial Content",
        headers,
        b"",
        should_close(request.headers),
        body_iter=_stream_range_handle(file_handle, byte_range),
        content_length=byte_range.length,
    )


def _stream_gzip_handle(
    file_handle: BinaryIO, chunk_size: int = 65536
) -> Iterator[bytes]:
    """Compress an already-open handle incrementally, then close it.

    Streaming through zlib avoids holding the whole file (and its compressed
    copy) in memory, so a large file cannot be a memory-amplification lever.
    """
    compressor = zlib.compressobj(level=6, wbits=31)
    try:
        while True:
            data = file_handle.read(chunk_size)
            if not data:
                break
            chunk = compressor.compress(data)
            if chunk:
                yield chunk
        tail = compressor.flush()
        if tail:
            yield tail
    finally:
        file_handle.close()


def _gzip_response(
    request: HttpRequest,
    file_handle: BinaryIO,
    headers: dict[str, str],
) -> HttpResponse:
    headers = dict(headers)
    headers["Content-Encoding"] = "gzip"
    headers["Vary"] = "Accept-Encoding"
    if "ETag" in headers:
        # Distinguish the gzip representation so a cache cannot serve it for an
        # identity request keyed on the same ETag.
        headers["ETag"] = headers["ETag"].rstrip('"') + '-gzip"'
    return HttpResponse(
        "HTTP/1.1 200 OK",
        headers,
        b"",
        should_close(request.headers),
        body_iter=_stream_gzip_handle(file_handle),
        use_chunked=True,
    )


def _full_file_response(
    request: HttpRequest,
    file_handle: BinaryIO,
    logger: Logger,
    headers: dict[str, str],
    file_size: int,
) -> HttpResponse:
    return HttpResponse(
        "HTTP/1.1 200 OK",
        headers,
        b"",
        should_close(request.headers),
        body_iter=_stream_handle(file_handle, file_size, logger),
        content_length=file_size,
    )


def _get_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig],
    options: FileServingOptions,
) -> HttpResponse:
    if resolved_path.is_dir():
        if options.autoindex:
            logger.log(logging.INFO, "autoindex", path=resolved_path.as_posix())
            return render_autoindex(request, resolved_path, cors_config)
        logger.log(logging.INFO, "file_not_found", path=resolved_path.as_posix())
        raise NotFound("file not found")
    if not (resolved_path.exists() and resolved_path.is_file()):
        logger.log(logging.INFO, "file_not_found", path=resolved_path.as_posix())
        raise NotFound("file not found")

    file_handle = open(resolved_path, "rb")  # pylint: disable=consider-using-with
    handle_owned_by_response = False
    try:
        response, handle_owned_by_response = _build_file_response(
            request, resolved_path, file_handle, logger, cors_config, options
        )
        return response
    finally:
        if not handle_owned_by_response:
            file_handle.close()


def _build_file_response(
    request: HttpRequest,
    resolved_path: Path,
    file_handle: BinaryIO,
    logger: Logger,
    cors_config: Optional[CorsConfig],
    options: FileServingOptions,
) -> tuple[HttpResponse, bool]:
    """Return the response and whether it now owns (and will close) the handle."""
    stat_result = os.fstat(file_handle.fileno())
    file_size = stat_result.st_size
    content_type = _content_type_for_path(resolved_path, options)
    etag = compute_etag(file_size, stat_result.st_mtime_ns)
    headers = _base_file_headers(
        request, content_type, etag, stat_result.st_mtime, cors_config, options
    )

    if is_not_modified(etag, stat_result.st_mtime, request.headers):
        return _not_modified_response(request, headers), False

    range_header = request.headers.get("range", "")
    if range_header and _if_range_satisfied(
        request.headers, etag, stat_result.st_mtime
    ):
        parsed = parse_range(range_header, file_size)
        if isinstance(parsed, ByteRange):
            return (
                _range_response(request, file_handle, parsed, headers, file_size),
                True,
            )
        if parsed is not None:
            raise RangeNotSatisfiable(file_size)

    if _gzip_eligible(content_type, file_size, options) and accepts_gzip(
        request.headers
    ):
        return _gzip_response(request, file_handle, headers), True

    logger.log(logging.INFO, "file_read_complete", path=resolved_path.as_posix())
    return _full_file_response(request, file_handle, logger, headers, file_size), True


def _atomic_write(resolved_path: Path, data: bytes) -> None:
    """Write ``data`` to ``resolved_path`` atomically via a temp file + os.replace.

    In-place ``open(path, "wb")`` truncates the live inode, so a concurrent
    reader streaming that file sees torn bytes and a body that no longer matches
    its Content-Length. Writing to a sibling temp file and renaming makes the
    swap atomic: readers see either the whole old file or the whole new one.
    """
    descriptor, temp_name = tempfile.mkstemp(
        dir=resolved_path.parent, prefix=".pyhttpd-"
    )
    temp_path = Path(temp_name)
    committed = False
    try:
        with os.fdopen(descriptor, "wb") as temp_handle:
            temp_handle.write(data)
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, resolved_path)
        committed = True
    finally:
        if not committed:
            temp_path.unlink(missing_ok=True)


def _write_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig],
    status_line: str,
) -> HttpResponse:
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(resolved_path, request.body)
    logger.log(
        logging.INFO,
        "file_write_complete",
        path=resolved_path.as_posix(),
        method=request.method,
        bytes_out=len(request.body),
    )
    headers = SECURITY_HEADERS.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(status_line, headers, b"", should_close(request.headers))


def _put_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    if resolved_path.is_dir():
        raise Forbidden("directory access denied")
    status_line = (
        "HTTP/1.1 204 No Content" if resolved_path.exists() else "HTTP/1.1 201 Created"
    )
    return _write_file_response(
        request, resolved_path, logger, cors_config, status_line
    )


def _delete_file_response(
    request: HttpRequest,
    resolved_path: Path,
    logger: Logger,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    if resolved_path.is_dir():
        raise Forbidden("directory access denied")
    if not resolved_path.exists():
        raise NotFound("file not found")
    resolved_path.unlink()
    logger.log(logging.INFO, "file_deleted", path=resolved_path.as_posix())
    headers = SECURITY_HEADERS.copy()
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse(
        "HTTP/1.1 204 No Content", headers, b"", should_close(request.headers)
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
    directory: str,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
    options: Optional[FileServingOptions] = None,
) -> RouteHandler:
    """Build a handler serving and writing files under the sandbox directory."""
    options = options or _DEFAULT_OPTIONS

    def dispatch(request: HttpRequest, resolved_path: Path) -> HttpResponse:
        if request.method == "GET":
            return _get_file_response(
                request, resolved_path, logger, cors_config, options
            )
        if request.method == "POST":
            return _write_file_response(
                request, resolved_path, logger, cors_config, "HTTP/1.1 201 Created"
            )
        if request.method == "PUT":
            return _put_file_response(request, resolved_path, logger, cors_config)
        if request.method == "DELETE":
            return _delete_file_response(request, resolved_path, logger, cors_config)
        return _unsupported_file_method(request, resolved_path, logger)

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        remainder = request.path[len(FILES_ENDPOINT_PREFIX) :]
        if _is_invalid_file_route(remainder):
            logger.log(logging.WARNING, "route_invalid", route=request.path)
            raise Forbidden("invalid file path")
        try:
            resolved_path = (
                Path(directory).resolve()
                if not remainder
                else resolve_sandbox_path(directory, remainder)
            )
            return dispatch(request, resolved_path)
        except ForbiddenPath as exc:
            logger.log(logging.WARNING, "forbidden_path", path=remainder)
            raise Forbidden("forbidden path") from exc
        except OSError as error:
            mapped = _client_error_for(error)
            if mapped is None:
                raise
            logger.log(
                logging.WARNING,
                "file_io_error",
                path=remainder,
                error_type=type(error).__name__,
            )
            raise mapped from error

    return handle


def make_index_handler(
    directory: str,
    logger: Logger,
    cors_config: Optional[CorsConfig] = None,
    document_name: str = "index.html",
) -> RouteHandler:
    """Build a handler serving the sandbox index document."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        if request.method != "GET":
            raise MethodNotAllowed(("GET", "HEAD"))
        try:
            resolved_path = resolve_sandbox_path(directory, document_name)
        except ForbiddenPath as exc:
            raise Forbidden("index path forbidden") from exc
        if resolved_path.exists() and resolved_path.is_file():
            return _streaming_file_response(request, resolved_path, logger, cors_config)
        return empty_response(request, cors_config, SECURITY_HEADERS)

    return handle
