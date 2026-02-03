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

LIMITER_LOGGER = CorrelationLoggerAdapter(
    logging.getLogger("http_server.pipeline.rate_limiting"), {}
)


def apply_rate_limit(
    rate_limiter: Optional[TokenBucketLimiter],
    client_ip: str,
    client_socket: socket.socket,
    client_address: tuple[str, int],
    request: Optional[HttpRequest],
) -> tuple[Optional[RateLimitDecision], bool, bool]:
    """Check rate limits and send response if exceeded.

    Returns:
        tuple[Optional[RateLimitDecision], bool, bool]:
            - RateLimitDecision: The decision result if allowed or dry-run.
            - bool: True if request processing should stop (limit exceeded).
            - bool: True if the connection should be terminated.
    """
    if rate_limiter is None or request is None:
        return None, False, False

    rate_decision = rate_limiter.consume(client_ip)

    client_addr_str = f"{client_address[0]}:{client_address[1]}"

    if rate_decision.allowed:
        if LIMITER_LOGGER.logger.isEnabledFor(logging.DEBUG):
            LIMITER_LOGGER.debug(
                "Rate limit check passed",
                extra={
                    "event": "rate_limit_allowed",
                    "client": client_addr_str,
                    "remaining_tokens": rate_decision.remaining,
                },
            )
        return rate_decision, False, False

    if rate_decision.dry_run:
        LIMITER_LOGGER.info(
            "Rate limit would be enforced (dry-run mode)",
            extra={
                "event": "rate_limit_dry_run",
                "client": client_addr_str,
                "limit": rate_decision.limit,
                "window_seconds": rate_decision.window_seconds,
            },
        )
        return rate_decision, False, False

    LIMITER_LOGGER.warning(
        "Rate limit enforced",
        extra={
            "event": "rate_limit_enforced",
            "client": client_addr_str,
            "limit_type": "ip",
            "limit": rate_decision.limit,
            "window_seconds": rate_decision.window_seconds,
            "rate_limit_headers": {
                "Retry-After": rate_decision.headers.get("Retry-After"),
                "X-RateLimit-Limit": rate_decision.headers.get("X-RateLimit-Limit"),
                "X-RateLimit-Remaining": rate_decision.headers.get(
                    "X-RateLimit-Remaining"
                ),
                "X-RateLimit-Reset": rate_decision.headers.get("X-RateLimit-Reset"),
            },
        },
    )

    response = rate_limited_response(rate_decision, request, SECURITY_HEADERS)
    # Ensure Keep-Alive by not setting close_connection
    send_response(client_socket, response)

    # Stop processing, but don't close connection (Keep-Alive)
    return None, True, False
