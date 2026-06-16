"""CORS negotiation for HTTP responses."""

from typing import Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import CorsConfig, HttpRequest, HttpResponse, should_close


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


def make_cors_middleware(
    cors_config: Optional[CorsConfig],
    security_headers: dict[str, str],
) -> Middleware:
    """Build middleware that answers CORS preflight requests directly."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        if is_preflight_request(request):
            return preflight_response(request, cors_config, security_headers)
        return nxt(request, ctx)

    return middleware
