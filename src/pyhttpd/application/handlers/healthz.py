"""Handler for /healthz requests."""

import logging
from typing import Callable, Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.rendering import healthz_response
from pyhttpd.domain import (
    SECURITY_HEADERS,
    DrainingState,
    HttpRequest,
    HttpResponse,
    Logger,
)

RouteHandler = Callable[[HttpRequest, RequestContext], HttpResponse]


def make_healthz_handler(
    draining_state: Optional[DrainingState],
    logger: Logger,
) -> RouteHandler:
    """Build a handler reporting server health, signalling 503 while draining."""

    def handle(_request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        is_draining = (
            draining_state.is_draining() if draining_state is not None else False
        )
        logger.log(logging.INFO, "healthz_check", draining=is_draining)
        return healthz_response(is_draining, SECURITY_HEADERS)

    return handle
