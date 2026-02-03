"""Unit tests for connection and rate limiting helpers."""

from server.domain.token_bucket import TokenBucketLimiter, TokenBucketSettings
from server.transport.connection_limiter import ConnectionLimiter


def test_connection_limiter_enforces_global_and_per_ip() -> None:
    """Ensure both global and per-IP quotas are respected."""

    limiter = ConnectionLimiter(max_connections=1, max_connections_per_ip=1)

    allowed, limit_type = limiter.acquire("127.0.0.1")
    assert allowed is True
    assert limit_type is None

    allowed, limit_type = limiter.acquire("127.0.0.1")
    assert allowed is False
    assert limit_type == "ip"

    limiter.release("127.0.0.1")
    allowed, limit_type = limiter.acquire("192.168.0.2")
    assert allowed is True
    assert limit_type is None

    allowed, limit_type = limiter.acquire("10.0.0.5")
    assert allowed is False
    assert limit_type == "global"


def test_token_bucket_blocks_after_burst_and_refills() -> None:
    """Token bucket should block after burst and refill on window boundary."""

    time_ns = [0]

    def now_ns() -> int:
        return time_ns[0]

    limiter = TokenBucketLimiter(
        TokenBucketSettings(rate_limit=2, window_ms=1000, burst_capacity=3),
        time_provider=now_ns,
    )

    assert limiter.consume("1.1.1.1").allowed is True
    assert limiter.consume("1.1.1.1").allowed is True
    assert limiter.consume("1.1.1.1").allowed is True

    blocked = limiter.consume("1.1.1.1")
    assert blocked.allowed is False
    assert blocked.remaining == 0

    time_ns[0] = 1_000_000_000
    refilled = limiter.consume("1.1.1.1")
    assert refilled.allowed is True
    assert refilled.headers["RateLimit-Limit"] == "2"
    assert float(refilled.headers["RateLimit-Reset"]) >= 0.0


def test_token_bucket_dry_run_allows_requests() -> None:
    """Dry-run mode should log limit hits while allowing traffic."""

    time_ns = [0]

    def now_ns() -> int:
        return time_ns[0]

    limiter = TokenBucketLimiter(
        TokenBucketSettings(
            rate_limit=1, window_ms=1000, burst_capacity=1, dry_run=True
        ),
        time_provider=now_ns,
    )

    first = limiter.consume("2.2.2.2")
    assert first.allowed is True
    second = limiter.consume("2.2.2.2")
    assert second.allowed is True
    assert second.dry_run is True
    assert second.remaining == 0
