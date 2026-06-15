"""Value types for token bucket rate limiting."""

from dataclasses import dataclass


@dataclass(slots=True)
class RateLimitDecision:
    """Outcome of a token bucket consume operation."""

    allowed: bool
    limit: int
    remaining: int
    reset_seconds: float
    headers: dict[str, str]
    dry_run: bool
    window_seconds: float


@dataclass(frozen=True)
class TokenBucketSettings:
    """Configuration for token bucket rate limiting."""

    rate_limit: int
    window_ms: int
    burst_capacity: int
    dry_run: bool = False


@dataclass(slots=True)
class BucketState:
    """Per-client token bucket state."""

    tokens: float
    last_refill_ns: int
