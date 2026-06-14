"""Token bucket rate limiting logic."""

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


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


class TokenBucketLimiter:
    """Token bucket limiter with optional dry-run behavior."""

    def __init__(
        self,
        settings: TokenBucketSettings,
        time_provider: Optional[Callable[[], int]] = None,
    ) -> None:
        self._rate_limit = max(0, settings.rate_limit)
        self._window_ns = max(0, settings.window_ms) * 1_000_000
        self._burst_capacity = max(settings.burst_capacity, self._rate_limit)
        self._dry_run = settings.dry_run
        self._now_provider = time_provider or time.monotonic_ns
        self._lock = threading.Lock()
        self._state: dict[str, BucketState] = {}

    def _now(self) -> int:
        return self._now_provider()

    def _get_state(self, client_ip: str) -> BucketState:
        state = self._state.get(client_ip)
        if state is None:
            state = BucketState(float(self._burst_capacity), self._now())
            self._state[client_ip] = state
        return state

    def _refill(self, state: BucketState, now_ns: int) -> float:
        tokens = state.tokens
        elapsed = now_ns - state.last_refill_ns
        if elapsed <= 0:
            return tokens

        windows = elapsed // self._window_ns
        if not windows:
            return tokens

        refill = windows * self._rate_limit
        state.last_refill_ns += windows * self._window_ns
        return min(self._burst_capacity, tokens + refill)

    def _reset_ns(self, state: BucketState, now_ns: int) -> int:
        elapsed_since_refill = now_ns - state.last_refill_ns
        return (
            self._window_ns - (elapsed_since_refill % self._window_ns)
        ) % self._window_ns

    def _decision(
        self,
        allowed: bool,
        tokens: float,
        reset_ns: int,
    ) -> RateLimitDecision:
        remaining = int(tokens)
        return RateLimitDecision(
            allowed=allowed or (not allowed and self._dry_run),
            limit=self._rate_limit,
            remaining=remaining if allowed else 0,
            reset_seconds=reset_ns / 1_000_000_000,
            headers=self._headers(remaining, reset_ns),
            dry_run=self._dry_run and not allowed,
            window_seconds=self._window_ns / 1_000_000_000,
        )

    def consume(self, client_ip: str) -> RateLimitDecision:
        """Consume a token for the given client IP and return the decision."""

        if self._rate_limit == 0 or self._window_ns == 0:
            return RateLimitDecision(True, 0, 0, 0.0, {}, self._dry_run, 0.0)

        now_ns = self._now()
        with self._lock:
            state = self._get_state(client_ip)
            tokens = self._refill(state, now_ns)
            allowed = tokens >= 1
            if allowed:
                tokens -= 1
            state.tokens = tokens
            return self._decision(allowed, tokens, self._reset_ns(state, now_ns))

    def _headers(self, remaining: int, reset_ns: int) -> dict[str, str]:
        """Build RateLimit headers for the current bucket state."""

        if self._rate_limit == 0:
            return {}
        reset_seconds = reset_ns / 1_000_000_000
        reset_value = f"{reset_seconds:.3f}".rstrip("0").rstrip(".") or "0"
        return {
            "RateLimit-Limit": str(self._rate_limit),
            "RateLimit-Remaining": str(max(remaining, 0)),
            "RateLimit-Reset": reset_value,
        }

    def reset(self, client_ip: str) -> None:
        """Reset the bucket state for a given client, freeing associated memory."""

        with self._lock:
            self._state.pop(client_ip, None)
