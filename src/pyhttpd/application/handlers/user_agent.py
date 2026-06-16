"""Handler for /user-agent requests."""

from typing import Optional

from pyhttpd.application.handlers._text import RouteHandler, make_text_handler
from pyhttpd.domain import CorsConfig, Logger


def make_user_agent_handler(
    logger: Logger, cors_config: Optional[CorsConfig] = None
) -> RouteHandler:
    """Build a handler returning the request User-Agent as text/plain."""
    return make_text_handler(
        logger,
        cors_config,
        lambda request: request.headers.get("user-agent", ""),
        "user_agent_request",
        log_content_length=False,
    )
