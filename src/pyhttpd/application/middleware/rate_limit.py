"""Rate limiting middleware for the application pipeline."""

import logging
from enum import Enum
from typing import Callable

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain.errors import RateLimited
from pyhttpd.domain.http import HttpRequest, HttpResponse
from pyhttpd.domain.ports import Logger, RateLimiter
from pyhttpd.domain.ratelimit import RateLimitDecision

ClientKeyResolver = Callable[[HttpRequest, RequestContext], str]


class RateLimitOutcome(Enum):
    """Classification of a rate limit decision."""

    ALLOWED = "allowed"
    DRY_RUN = "dry_run"
    ENFORCED = "enforced"


def classify(decision: RateLimitDecision) -> RateLimitOutcome:
    """Classify a decision as allowed, dry-run, or enforced."""
    if decision.allowed:
        return RateLimitOutcome.ALLOWED
    if decision.dry_run:
        return RateLimitOutcome.DRY_RUN
    return RateLimitOutcome.ENFORCED


def _log_enforced(logger: Logger, client_key: str, decision: RateLimitDecision) -> None:
    logger.log(
        logging.WARNING,
        "rate_limit_enforced",
        client=client_key,
        limit_type="ip",
        limit=decision.limit,
        window_seconds=decision.window_seconds,
        rate_limit_headers={
            "Retry-After": decision.headers.get("Retry-After"),
            "X-RateLimit-Limit": decision.headers.get("X-RateLimit-Limit"),
            "X-RateLimit-Remaining": decision.headers.get("X-RateLimit-Remaining"),
            "X-RateLimit-Reset": decision.headers.get("X-RateLimit-Reset"),
        },
    )


def make_rate_limit_middleware(
    rate_limiter: RateLimiter,
    logger: Logger,
    client_key_of: ClientKeyResolver,
) -> Middleware:
    """Build middleware enforcing per-client token bucket rate limits."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        client_key = client_key_of(request, ctx)
        decision = rate_limiter.consume(client_key)
        if classify(decision) is RateLimitOutcome.ENFORCED:
            _log_enforced(logger, client_key, decision)
            raise RateLimited(decision)
        ctx.rate_decision = decision
        return nxt(request, ctx)

    return middleware
