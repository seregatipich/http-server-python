"""Rate limiting middleware logic."""

import logging
import socket
from typing import Optional

from server.bootstrap.config import SECURITY_HEADERS
from server.domain.correlation_id import CorrelationLoggerAdapter
from server.domain.http_types import HttpRequest
from server.domain.response_builders import rate_limited_response
from server.domain.token_bucket import RateLimitDecision, TokenBucketLimiter
from server.pipeline.io import send_response

LIMITER_LOGGER = CorrelationLoggerAdapter(logging.getLogger("http_server.limiter"), {})


def apply_rate_limit(
    rate_limiter: Optional[TokenBucketLimiter],
    client_ip: str,
    client_socket: socket.socket,
    client_address: tuple[str, int],
    request: Optional[HttpRequest],
) -> tuple[Optional[RateLimitDecision], bool]:
    """Check rate limits and send response if exceeded.

    Returns:
        tuple[Optional[RateLimitDecision], bool]:
            - RateLimitDecision: The decision result if allowed or dry-run.
            - bool: True if the connection should be terminated (limit exceeded),
                    False otherwise.
    """
    if rate_limiter is None or request is None:
        return None, False

    rate_decision = rate_limiter.consume(client_ip)

    if rate_decision.allowed or rate_decision.dry_run:
        return rate_decision, False

    LIMITER_LOGGER.warning(
        "Rate limit exceeded",
        extra={
            "client": client_address,
            "limit_type": "ip",
            "limit": rate_decision.limit,
        },
    )
    send_response(
        client_socket, rate_limited_response(rate_decision, request, SECURITY_HEADERS)
    )
    return None, True
