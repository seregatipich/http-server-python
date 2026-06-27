"""Request-scoped context carried through the middleware chain."""

from dataclasses import dataclass
from typing import Dict, Optional

from pyhttpd.domain import RateLimitDecision


@dataclass
class RequestContext:
    """Mutable state shared across middleware for a single request."""

    correlation_id: Optional[str]
    start_ns: int
    rate_decision: Optional[RateLimitDecision] = None
    principal: Optional[str] = None
    error_format: str = "text"
    session: Optional[Dict[str, object]] = None
