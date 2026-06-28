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
    allow_chunked_requests: bool = False
    expect_continue: bool = False
    session_store: Optional[Any] = None
    session_policy: Optional[Any] = None
    enable_sse: bool = False
    enable_websocket: bool = False
    enable_http2: bool = False
    proxy_targets: tuple = ()
    proxy_timeout: float = 30.0
    vhost_directories: Optional[dict] = None
    access_logger: Optional[Any] = None
    client_cert_roles: Optional[dict] = None
    tls_context: Optional[Any] = None
