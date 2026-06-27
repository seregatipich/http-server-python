"""Pure HTTP response builders."""

import gzip
import json
import logging
from collections.abc import Iterable
from dataclasses import replace
from typing import Callable, Optional, Tuple

from pyhttpd.application.context import RequestContext
from pyhttpd.application.cors_headers import apply_cors_headers
from pyhttpd.domain import (
    SECURITY_HEADERS,
    BadGateway,
    BadRequest,
    CorsConfig,
    Forbidden,
    ForbiddenPath,
    GatewayTimeout,
    HttpError,
    HttpRequest,
    HttpResponse,
    Logger,
    MethodNotAllowed,
    NotFound,
    RangeNotSatisfiable,
    RateLimitDecision,
    RateLimited,
    RequestEntityTooLarge,
    RequestTimeout,
    ServiceUnavailable,
    Unauthorized,
    should_close,
)

_COMPRESSION_LOGGER = logging.getLogger("http_server.handlers.system")

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]
TextExtractor = Callable[[HttpRequest], str]


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
    payload: bytes, headers: dict[str, str], compression_logger: logging.Logger
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
    cors_config: Optional[CorsConfig],
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
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Return a 200 OK response with no body."""
    return _request_response("HTTP/1.1 200 OK", request, cors_config, security_headers)


def text_response(
    message: str,
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
    compression_logger: logging.Logger,
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


def make_text_handler(
    logger: Logger,
    cors_config: Optional[CorsConfig],
    extract: TextExtractor,
    log_event: str,
    log_content_length: bool = True,
) -> RouteHandler:
    """Build a text/plain route handler that logs a debug event."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        if request.method != "GET":
            raise MethodNotAllowed(("GET", "HEAD"))
        content = extract(request)
        fields = {"content_length": len(content)} if log_content_length else {}
        logger.log(logging.DEBUG, log_event, **fields)
        return text_response(
            content, request, cors_config, SECURITY_HEADERS, _COMPRESSION_LOGGER
        )

    return handle


def not_found_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Return a 404 response reusing the connection preference."""
    return _request_response(
        "HTTP/1.1 404 Not Found",
        request,
        cors_config,
        security_headers,
    )


def forbidden_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Produce a 403 response honoring the caller's connection preference."""
    return _request_response(
        "HTTP/1.1 403 Forbidden",
        request,
        cors_config,
        security_headers,
    )


def unauthorized_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
    challenge: str,
) -> HttpResponse:
    """Produce a 401 response advertising the authentication challenge."""
    return _request_response(
        "HTTP/1.1 401 Unauthorized",
        request,
        cors_config,
        security_headers,
        extra_headers={"WWW-Authenticate": challenge},
    )


def bad_request_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
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
    decision: RateLimitDecision,
    request: Optional[HttpRequest],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Create a 429 response populated with RateLimit headers."""
    retry_after = max(1, int(decision.reset_seconds)) if decision.reset_seconds else 1
    body = b"Rate limit exceeded"
    return _basic_response(
        "HTTP/1.1 429 Too Many Requests",
        security_headers,
        body,
        {"Retry-After": str(retry_after), **decision.headers},
        _request_close_preference(request),
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
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
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


def range_not_satisfiable_response(
    file_size: int,
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Produce a 416 response advertising the valid byte extent."""
    return _request_response(
        "HTTP/1.1 416 Range Not Satisfiable",
        request,
        cors_config,
        security_headers,
        extra_headers={"Content-Range": f"bytes */{file_size}"},
    )


def request_timeout_response(security_headers: dict[str, str]) -> HttpResponse:
    """Produce a 408 response that always closes the connection."""
    return _basic_response(
        "HTTP/1.1 408 Request Timeout",
        security_headers,
        extra_headers={"Connection": "close"},
    )


def internal_error_response(
    request: Optional[HttpRequest], security_headers: dict[str, str]
) -> HttpResponse:
    """Produce a 500 response with security headers and no CORS, honoring close."""
    return _basic_response(
        "HTTP/1.1 500 Internal Server Error",
        security_headers,
        close_connection=_request_close_preference(request),
    )


def bad_gateway_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Produce a 502 response when an upstream is unreachable or invalid."""
    return _request_response(
        "HTTP/1.1 502 Bad Gateway", request, cors_config, security_headers
    )


def gateway_timeout_response(
    request: Optional[HttpRequest],
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> HttpResponse:
    """Produce a 504 response when an upstream exceeds the deadline."""
    return _request_response(
        "HTTP/1.1 504 Gateway Timeout", request, cors_config, security_headers
    )


def apply_error_format(
    response: HttpResponse,
    error_format: str,
    request_id: Optional[str] = None,
) -> HttpResponse:
    """Rewrite an error response body as JSON when ``error_format`` is ``json``.

    The text format is byte-preserving (the response is returned untouched).
    Streaming responses are never rewritten, since error responses never stream.
    """
    if error_format != "json" or response.use_chunked or response.body_iter is not None:
        return response
    _, _, remainder = response.status_line.partition(" ")
    code, _, reason = remainder.partition(" ")
    payload = {"error": reason, "status": int(code), "request_id": request_id}
    body = json.dumps(payload).encode()
    headers = {**response.headers, "Content-Type": "application/json"}
    return replace(response, headers=headers, body=body, content_length=None)


class ErrorMapper:
    """Dispatches domain errors to their byte-exact response builders."""

    @staticmethod
    def to_response(  # pylint: disable=too-many-return-statements
        error: HttpError,
        request: Optional[HttpRequest],
        cors_config: Optional[CorsConfig],
        error_format: str = "text",
        request_id: Optional[str] = None,
    ) -> HttpResponse:
        """Map a domain HttpError to its corresponding HTTP response."""
        response = ErrorMapper._build(error, request, cors_config)
        return apply_error_format(response, error_format, request_id)

    @staticmethod
    def _build(  # pylint: disable=too-many-return-statements
        error: HttpError,
        request: Optional[HttpRequest],
        cors_config: Optional[CorsConfig],
    ) -> HttpResponse:
        if isinstance(error, BadRequest):
            return bad_request_response(request, cors_config, SECURITY_HEADERS)
        if isinstance(error, Unauthorized):
            return unauthorized_response(
                request, cors_config, SECURITY_HEADERS, error.challenge
            )
        if isinstance(error, (Forbidden, ForbiddenPath)):
            return forbidden_response(request, cors_config, SECURITY_HEADERS)
        if isinstance(error, NotFound):
            return not_found_response(request, cors_config, SECURITY_HEADERS)
        if isinstance(error, MethodNotAllowed):
            return method_not_allowed_response(
                request, cors_config, SECURITY_HEADERS, error.allowed
            )
        if isinstance(error, RequestEntityTooLarge):
            return entity_too_large_response(SECURITY_HEADERS)
        if isinstance(error, RequestTimeout):
            return request_timeout_response(SECURITY_HEADERS)
        if isinstance(error, RangeNotSatisfiable):
            return range_not_satisfiable_response(
                error.file_size, request, cors_config, SECURITY_HEADERS
            )
        if isinstance(error, RateLimited):
            return rate_limited_response(error.decision, request, SECURITY_HEADERS)
        if isinstance(error, ServiceUnavailable):
            return draining_response(SECURITY_HEADERS)
        if isinstance(error, BadGateway):
            return bad_gateway_response(request, cors_config, SECURITY_HEADERS)
        if isinstance(error, GatewayTimeout):
            return gateway_timeout_response(request, cors_config, SECURITY_HEADERS)
        return internal_error_response(request, SECURITY_HEADERS)

    @staticmethod
    def internal_error(
        request: Optional[HttpRequest],
        cors_config: Optional[CorsConfig],  # pylint: disable=unused-argument
        error_format: str = "text",
        request_id: Optional[str] = None,
    ) -> HttpResponse:
        """Produce the 500 response for unexpected, non-HttpError failures."""
        response = internal_error_response(request, SECURITY_HEADERS)
        return apply_error_format(response, error_format, request_id)
