"""System handlers for echo, user-agent, and health checks."""

import logging
from typing import Optional

from server.bootstrap.config import SECURITY_HEADERS
from server.domain.correlation_id import CorrelationLoggerAdapter
from server.domain.http_types import HttpRequest, HttpResponse
from server.domain.response_builders import healthz_response, text_response
from server.lifecycle.state import ServerLifecycle
from server.security.cors import CorsConfig

SYSTEM_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.handlers.system"), {}
)


def handle_echo(
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    """Handle /echo/ requests by returning the path suffix."""
    content = request.path[6:]
    if SYSTEM_LOGGER.logger.isEnabledFor(logging.DEBUG):
        SYSTEM_LOGGER.debug(
            "Echo request processed",
            extra={"event": "echo_request", "content_length": len(content)},
        )
    return text_response(content, request, cors_config, SECURITY_HEADERS, SYSTEM_LOGGER)


def handle_user_agent(
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    """Handle /user-agent requests by returning the User-Agent header."""
    agent = request.headers.get("user-agent", "")
    if SYSTEM_LOGGER.logger.isEnabledFor(logging.DEBUG):
        SYSTEM_LOGGER.debug(
            "User-agent request processed", extra={"event": "user_agent_request"}
        )
    return text_response(agent, request, cors_config, SECURITY_HEADERS, SYSTEM_LOGGER)


def handle_healthz(
    lifecycle: Optional[ServerLifecycle],
) -> HttpResponse:
    """Handle /healthz requests with current server state."""
    is_draining = lifecycle.is_draining() if lifecycle is not None else False
    SYSTEM_LOGGER.info(
        "Health check performed",
        extra={"event": "healthz_check", "draining": is_draining},
    )
    return healthz_response(is_draining, SECURITY_HEADERS)
