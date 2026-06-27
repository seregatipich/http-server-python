"""Context object shared across worker threads."""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class WorkerContext:  # pylint: disable=too-many-instance-attributes
    """Dependencies shared across handler threads."""

    directory: str
    connection_limiter: Optional[Any] = None
    rate_limiter: Optional[Any] = None
    lifecycle: Optional[Any] = None
    config: Optional[Any] = None
    cors_config: Optional[Any] = None
    authenticator: Optional[Any] = None
    metrics_sink: Optional[Any] = None
    file_options: Optional[Any] = None
    phase_timeouts: Optional[Any] = None
    error_format: str = "text"
