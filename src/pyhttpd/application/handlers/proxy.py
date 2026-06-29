"""Reverse-proxy dispatch that forwards matching mounts to an upstream.

Wraps the default router: a request whose path falls under a configured mount is
forwarded to the upstream and its response streamed back; everything else falls
through to the wrapped dispatch unchanged.
"""

import logging
from typing import Callable, Dict, Optional, Sequence

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler
from pyhttpd.domain import HttpRequest, HttpResponse, Logger
from pyhttpd.domain.proxy import (
    ProxyTarget,
    UpstreamResponse,
    filter_request_headers,
    filter_response_headers,
    upstream_path,
)

Forwarder = Callable[
    [ProxyTarget, str, str, Dict[str, str], bytes, float], UpstreamResponse
]


def make_proxy_dispatch(
    targets: Sequence[ProxyTarget],
    forwarder: Forwarder,
    client_ip: str,
    timeout: float,
    logger: Logger,
    fallback: Handler,
) -> Handler:
    """Return a dispatch that proxies matching mounts and falls back otherwise."""

    def dispatch(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        target = _match(targets, request.path)
        if target is None:
            return fallback(request, ctx)
        return _proxy(request, target, forwarder, client_ip, timeout, logger)

    return dispatch


def _match(targets: Sequence[ProxyTarget], path: str) -> Optional[ProxyTarget]:
    for target in targets:
        mount = target.mount.rstrip("/")
        if path == mount or path.startswith(mount + "/"):
            return target
    return None


def _proxy(
    request: HttpRequest,
    target: ProxyTarget,
    forwarder: Forwarder,
    client_ip: str,
    timeout: float,
    logger: Logger,
) -> HttpResponse:
    path = upstream_path(target, request.raw_path or request.path, request.query)
    headers = filter_request_headers(request.headers, target, client_ip, "http")
    logger.log(
        logging.INFO, "proxy_forward", mount=target.mount, upstream=target.authority
    )
    response = forwarder(target, request.method, path, headers, request.body, timeout)
    return _build_response(response)


def _build_response(response: UpstreamResponse) -> HttpResponse:
    headers, content_length = _split_content_length(
        filter_response_headers(response.headers)
    )
    status_line = f"HTTP/1.1 {response.status} {response.reason}"
    return HttpResponse(
        status_line,
        headers,
        b"",
        close_connection=True,
        body_iter=response.body,
        use_chunked=content_length is None,
        content_length=content_length,
        streaming=True,
    )


def _split_content_length(
    headers: Dict[str, str],
) -> tuple[Dict[str, str], Optional[int]]:
    kept: Dict[str, str] = {}
    length: Optional[int] = None
    for name, value in headers.items():
        if name.lower() == "content-length":
            try:
                length = int(value)
            except ValueError:
                length = None
        else:
            kept[name] = value
    return kept, length
