"""System handlers for echo, user-agent, and health checks."""

import logging
from typing import Optional

from server.bootstrap.config import SECURITY_HEADERS
from server.domain.correlation_id import CorrelationLoggerAdapter
from server.domain.http_types import HttpRequest, HttpResponse
from server.domain.response_builders import healthz_response, text_response
from server.lifecycle.state import ServerLifecycle
from server.security.cors import CorsConfig

COMPRESSION_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.compression"), {}
)


def handle_echo(
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    """Handle /echo/ requests by returning the path suffix."""
    content = request.path[6:]  # Strip "/echo/"
    return text_response(
        content, request, cors_config, SECURITY_HEADERS, COMPRESSION_LOGGER
    )


def handle_user_agent(
    request: HttpRequest,
    cors_config: Optional[CorsConfig],
) -> HttpResponse:
    """Handle /user-agent requests by returning the User-Agent header."""
    agent = request.headers.get("user-agent", "")
    return text_response(
        agent, request, cors_config, SECURITY_HEADERS, COMPRESSION_LOGGER
    )


def handle_healthz(
    lifecycle: Optional[ServerLifecycle],
) -> HttpResponse:
    """Handle /healthz requests with current server state."""
    is_draining = lifecycle.is_draining() if lifecycle is not None else False
    return healthz_response(is_draining, SECURITY_HEADERS)
