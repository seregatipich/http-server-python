"""Upstream forwarding over http.client for the reverse proxy."""

import http.client
import socket
import ssl
from typing import Dict, Iterator

from pyhttpd.domain import BadGateway, BadRequest, GatewayTimeout
from pyhttpd.domain.proxy import ProxyTarget, UpstreamResponse

_STREAM_CHUNK = 65536


def forward(
    target: ProxyTarget,
    method: str,
    path: str,
    headers: Dict[str, str],
    body: bytes,
    timeout: float,
) -> UpstreamResponse:
    """Forward a request to the upstream and return its streamed response."""
    connection = _open_connection(target, timeout)
    try:
        connection.request(method, path, body=body or None, headers=headers)
        response = connection.getresponse()
    except (TimeoutError, socket.timeout) as exc:
        connection.close()
        raise GatewayTimeout("upstream timed out") from exc
    except UnicodeEncodeError as exc:
        connection.close()
        raise BadRequest(
            "request contains characters the upstream cannot accept"
        ) from exc
    except (OSError, http.client.HTTPException) as exc:
        connection.close()
        raise BadGateway("upstream request failed") from exc
    response_headers = dict(response.getheaders())
    return UpstreamResponse(
        status=response.status,
        reason=response.reason,
        headers=response_headers,
        body=_stream_body(connection, response),
    )


def _open_connection(target: ProxyTarget, timeout: float) -> http.client.HTTPConnection:
    if target.scheme == "https":
        context = ssl.create_default_context()
        return http.client.HTTPSConnection(
            target.host, target.port, timeout=timeout, context=context
        )
    return http.client.HTTPConnection(target.host, target.port, timeout=timeout)


def _stream_body(
    connection: http.client.HTTPConnection, response: http.client.HTTPResponse
) -> Iterator[bytes]:
    try:
        while True:
            chunk = response.read(_STREAM_CHUNK)
            if not chunk:
                return
            yield chunk
    finally:
        connection.close()
