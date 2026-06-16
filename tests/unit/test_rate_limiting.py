"""Unit tests for request rate limiting middleware."""

from unittest.mock import Mock

import pytest

from pyhttpd.adapters.ratelimit.token_bucket import TokenBucketLimiter
from pyhttpd.application.context import RequestContext
from pyhttpd.application.middleware.rate_limit import (
    RateLimitOutcome,
    classify,
    make_rate_limit_middleware,
)
from pyhttpd.domain import HttpRequest, RateLimited, TokenBucketSettings
from pyhttpd.domain.ratelimit import RateLimitDecision
from tests.unit._helpers import PASSTHROUGH, make_request


def make_decision(allowed: bool, dry_run: bool) -> RateLimitDecision:
    """Construct a rate limit decision for classification tests."""
    return RateLimitDecision(
        allowed=allowed,
        limit=1,
        remaining=0,
        reset_seconds=1.0,
        headers={},
        dry_run=dry_run,
        window_seconds=1.0,
    )


def make_limiter(dry_run: bool = False) -> TokenBucketLimiter:
    """Build a limiter that allows one request per window."""
    return TokenBucketLimiter(
        TokenBucketSettings(
            rate_limit=1,
            window_ms=1000,
            burst_capacity=1,
            dry_run=dry_run,
        ),
        time_provider=lambda: 0,
    )


def run_middleware(limiter: TokenBucketLimiter, request: HttpRequest):
    """Drive the rate-limit middleware with a sentinel terminal handler."""
    middleware = make_rate_limit_middleware(
        limiter, Mock(), lambda forwarded_request, ctx: "127.0.0.1"
    )
    ctx = RequestContext(correlation_id=None, start_ns=0)
    response = middleware(request, ctx, lambda *_: PASSTHROUGH)
    return response, ctx


def test_classify_allowed_decision() -> None:
    """A decision under the limit classifies as allowed."""
    assert classify(make_decision(allowed=True, dry_run=False)) is (
        RateLimitOutcome.ALLOWED
    )


def test_classify_dry_run_decision() -> None:
    """An over-limit decision in dry-run mode classifies as dry-run."""
    assert classify(make_decision(allowed=False, dry_run=True)) is (
        RateLimitOutcome.DRY_RUN
    )


def test_classify_enforced_decision() -> None:
    """An over-limit decision in enforcing mode classifies as enforced."""
    assert classify(make_decision(allowed=False, dry_run=False)) is (
        RateLimitOutcome.ENFORCED
    )


def test_rate_limit_allowed_sets_decision_and_continues() -> None:
    """Allowed requests record the decision on the context and continue."""
    response, ctx = run_middleware(make_limiter(), make_request())

    assert response is PASSTHROUGH
    assert ctx.rate_decision is not None
    assert ctx.rate_decision.allowed is True


def test_rate_limit_dry_run_continues_processing() -> None:
    """Dry-run mode records a decision without raising."""
    limiter = make_limiter(dry_run=True)
    run_middleware(limiter, make_request())

    response, ctx = run_middleware(limiter, make_request())

    assert response is PASSTHROUGH
    assert ctx.rate_decision is not None
    assert ctx.rate_decision.dry_run is True


def test_rate_limit_enforced_raises() -> None:
    """Exceeded limits raise RateLimited and stop processing."""
    limiter = make_limiter()
    run_middleware(limiter, make_request())

    with pytest.raises(RateLimited):
        run_middleware(limiter, make_request())


def test_consume_with_zero_rate_limit_always_allows() -> None:
    """A limiter built with rate_limit=0 allows every request with no headers."""
    limiter = TokenBucketLimiter(
        TokenBucketSettings(
            rate_limit=0,
            window_ms=1000,
            burst_capacity=0,
            dry_run=False,
        ),
        time_provider=lambda: 0,
    )

    decision = limiter.consume("203.0.113.7")

    assert decision.allowed is True
    assert decision.headers == {}


def test_reset_clears_per_client_state() -> None:
    """reset(ip) discards the bucket so the client is allowed again."""
    limiter = make_limiter()

    assert limiter.consume("198.51.100.4").allowed is True
    assert limiter.consume("198.51.100.4").allowed is False

    limiter.reset("198.51.100.4")

    assert limiter.consume("198.51.100.4").allowed is True


def test_tokens_refill_after_window_elapses() -> None:
    """Advancing the clock by one window refills an exhausted client's bucket."""
    current_ns = 0

    def clock() -> int:
        return current_ns

    limiter = TokenBucketLimiter(
        TokenBucketSettings(
            rate_limit=1,
            window_ms=1000,
            burst_capacity=1,
            dry_run=False,
        ),
        time_provider=clock,
    )

    assert limiter.consume("192.0.2.10").allowed is True
    assert limiter.consume("192.0.2.10").allowed is False

    current_ns = 1000 * 1_000_000

    assert limiter.consume("192.0.2.10").allowed is True
