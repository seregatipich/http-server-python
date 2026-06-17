"""CORS preflight middleware."""

from typing import Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.cors_headers import is_preflight_request, preflight_response
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import CorsConfig, HttpRequest, HttpResponse


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
