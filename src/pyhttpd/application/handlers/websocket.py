"""WebSocket opening-handshake handler for the /ws route."""

import logging
from typing import Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.handlers.ws_echo import make_ws_echo_driver
from pyhttpd.application.rendering import RouteHandler
from pyhttpd.domain import BadRequest, DrainingState, HttpRequest, HttpResponse, Logger
from pyhttpd.domain.websocket import compute_accept, is_websocket_upgrade


def make_websocket_handler(
    draining_state: Optional[DrainingState], logger: Logger
) -> RouteHandler:
    """Build the handler that performs the WebSocket upgrade handshake."""
    driver = make_ws_echo_driver(draining_state, logger)

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        if not is_websocket_upgrade(request.headers):
            raise BadRequest("invalid websocket upgrade request")
        accept = compute_accept(request.headers["sec-websocket-key"])
        logger.log(logging.INFO, "websocket_upgrade")
        return HttpResponse(
            "HTTP/1.1 101 Switching Protocols",
            {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Accept": accept,
            },
            b"",
            close_connection=True,
            upgrade=driver,
        )

    return handle
