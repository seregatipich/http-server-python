"""Handler for /user-agent requests."""

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


def make_user_agent_handler(
    logger: Logger, cors_config: Optional[CorsConfig] = None
) -> RouteHandler:
    """Build a handler returning the request User-Agent as text/plain."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        agent = request.headers.get("user-agent", "")
        logger.log(logging.DEBUG, "user_agent_request")
        return text_response(
            agent, request, cors_config, SECURITY_HEADERS, _COMPRESSION_LOGGER
        )

    return handle
