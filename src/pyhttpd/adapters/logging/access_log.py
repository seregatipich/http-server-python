"""Common/Combined Log Format access logging.

Emits one apache-style line per response on a dedicated logger, separate from the
structured JSON application log, so operators can feed it to standard tooling.
"""

import logging
from datetime import datetime, timezone

from pyhttpd.domain import HttpRequest, HttpResponse


def combined_log_line(
    client_ip: str,
    request: HttpRequest,
    status: int,
    body_bytes: str,
    timestamp: str,
) -> str:
    """Build a Combined Log Format line for a served request."""
    referer = request.headers.get("referer", "-")
    user_agent = request.headers.get("user-agent", "-")
    return (
        f"{client_ip} - - [{timestamp}] "
        f'"{request.method} {_target(request)} HTTP/1.1" '
        f'{status} {body_bytes} "{referer}" "{user_agent}"'
    )


def _target(request: HttpRequest) -> str:
    return f"{request.path}?{request.query}" if request.query else request.path


def _status_code(status_line: str) -> int:
    try:
        return int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def _body_size(response: HttpResponse) -> str:
    if response.content_length is not None:
        return str(response.content_length)
    if response.streaming or response.use_chunked or response.body_iter is not None:
        return "-"
    return str(len(response.body))


class AccessLogger:
    """Records a Combined Log Format line per response."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def record(
        self, client_ip: str, request: HttpRequest, response: HttpResponse
    ) -> None:
        """Emit the access-log line for a completed response."""
        timestamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
        self._logger.info(
            combined_log_line(
                client_ip,
                request,
                _status_code(response.status_line),
                _body_size(response),
                timestamp,
            )
        )
