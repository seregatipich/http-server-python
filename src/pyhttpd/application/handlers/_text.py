"""Shared builder for text/plain route handlers."""

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
TextExtractor = Callable[[HttpRequest], str]


def make_text_handler(
    logger: Logger,
    cors_config: Optional[CorsConfig],
    extract: TextExtractor,
    log_event: str,
    log_content_length: bool = True,
) -> RouteHandler:
    """Build a text/plain handler that logs a debug event and compresses output."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        content = extract(request)
        fields = {"content_length": len(content)} if log_content_length else {}
        logger.log(logging.DEBUG, log_event, **fields)
        return text_response(
            content, request, cors_config, SECURITY_HEADERS, _COMPRESSION_LOGGER
        )

    return handle
