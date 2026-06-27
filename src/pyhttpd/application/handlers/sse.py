"""Server-Sent Events streaming endpoint.

Reuses the chunked streaming response path; the generator is drain-aware so a
graceful shutdown ends the stream rather than hanging for the grace period. Each
connected client pins a worker thread for the stream's lifetime, so the overall
connection cap bounds concurrent subscribers.
"""

import logging
import time
from typing import Iterator, Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.rendering import RouteHandler
from pyhttpd.domain import (
    DrainingState,
    HttpRequest,
    HttpResponse,
    Logger,
    MethodNotAllowed,
    parse_query,
)

DEFAULT_EVENT_COUNT = 5
MAX_EVENT_COUNT = 1000
EVENT_INTERVAL_SECONDS = 0.1


def make_sse_handler(
    draining_state: Optional[DrainingState], logger: Logger
) -> RouteHandler:
    """Build the text/event-stream handler for the /events route."""

    def handle(request: HttpRequest, _ctx: RequestContext) -> HttpResponse:
        if request.method != "GET":
            raise MethodNotAllowed(("GET",))
        count = _event_count(request.query)
        logger.log(logging.DEBUG, "sse_stream_started", count=count)
        return HttpResponse(
            "HTTP/1.1 200 OK",
            {"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
            b"",
            close_connection=True,
            body_iter=_event_stream(draining_state, count),
            use_chunked=True,
            streaming=True,
        )

    return handle


def _event_count(query: str) -> int:
    raw = parse_query(query).get("count", [str(DEFAULT_EVENT_COUNT)])[0]
    try:
        count = int(raw)
    except ValueError:
        count = DEFAULT_EVENT_COUNT
    return max(1, min(count, MAX_EVENT_COUNT))


def _event_stream(
    draining_state: Optional[DrainingState], count: int
) -> Iterator[bytes]:
    for index in range(1, count + 1):
        if draining_state is not None and draining_state.is_draining():
            return
        if index > 1:
            time.sleep(EVENT_INTERVAL_SECONDS)
        yield f"id: {index}\nevent: tick\ndata: {index}\n\n".encode()
