"""Context object shared across worker threads."""

from dataclasses import dataclass
from typing import Optional

from server.bootstrap.config import ServerConfig
from server.lifecycle.state import ServerLifecycle
from server.security.cors import CorsConfig
from server.domain.token_bucket import TokenBucketLimiter
from server.transport.connection_limiter import ConnectionLimiter


@dataclass
class WorkerContext:
    """Dependencies shared across handler threads."""

    directory: str
    connection_limiter: Optional[ConnectionLimiter] = None
    rate_limiter: Optional[TokenBucketLimiter] = None
    lifecycle: Optional[ServerLifecycle] = None
    config: Optional[ServerConfig] = None
    cors_config: Optional[CorsConfig] = None
