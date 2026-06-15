"""Request-scoped context carried through the middleware chain."""

from dataclasses import dataclass
from typing import Optional

from pyhttpd.domain.ratelimit import RateLimitDecision


@dataclass
class RequestContext:
    """Mutable state shared across middleware for a single request."""

    correlation_id: Optional[str]
    start_ns: int
    rate_decision: Optional[RateLimitDecision] = None
    request_wants_close: bool = True
