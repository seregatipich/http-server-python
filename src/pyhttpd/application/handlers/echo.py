"""Handler for /echo/* requests."""

from typing import Optional

from pyhttpd.application.rendering import RouteHandler, make_text_handler
from pyhttpd.domain import CorsConfig, Logger


def make_echo_handler(
    logger: Logger, cors_config: Optional[CorsConfig] = None
) -> RouteHandler:
    """Build a handler echoing the path suffix as text/plain."""
    return make_text_handler(
        logger, cors_config, lambda request: request.path[6:], "echo_request"
    )
