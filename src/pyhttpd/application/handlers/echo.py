"""Handler for /echo/* requests."""

import logging
from typing import Callable, Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.rendering import text_response
from pyhttpd.domain import (
    SECURITY_HEADERS,
    CorsConfig,
    HttpRequest,
    HttpResponse,
    Logger,
)

_COMPRESSION_LOGGER = logging.getLogger("http_server.handlers.system")

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]


def make_echo_handler(
    logger: Logger, cors_config: Optional[CorsConfig] = None
) -> RouteHandler:
    """Build a handler echoing the path suffix as text/plain."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        content = request.path[6:]
        logger.log(logging.DEBUG, "echo_request", content_length=len(content))
        return text_response(
            content, request, cors_config, SECURITY_HEADERS, _COMPRESSION_LOGGER
        )

    return handle
