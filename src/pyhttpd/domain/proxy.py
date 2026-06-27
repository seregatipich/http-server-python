"""Pure reverse-proxy helpers: target parsing and hop-by-hop header handling."""

from dataclasses import dataclass
from typing import Dict, Iterator
from urllib.parse import urlsplit

# RFC 7230 section 6.1: headers meaningful only on a single transport hop and
# never forwarded end to end.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass
class UpstreamResponse:
    """An upstream response with a lazily-streamed body."""

    status: int
    reason: str
    headers: Dict[str, str]
    body: Iterator[bytes]


@dataclass(frozen=True)
class ProxyTarget:
    """An upstream a mount prefix forwards to."""

    mount: str
    scheme: str
    host: str
    port: int
    base_path: str

    @property
    def authority(self) -> str:
        """Return the host[:port] used for the upstream Host header."""
        default_port = 443 if self.scheme == "https" else 80
        if self.port == default_port:
            return self.host
        return f"{self.host}:{self.port}"


def parse_proxy_pass(spec: str) -> ProxyTarget:
    """Parse a ``mount=upstream_url`` spec into a ProxyTarget."""
    mount, separator, raw_url = spec.partition("=")
    if not separator or not mount.startswith("/"):
        raise ValueError(f"invalid --proxy-pass spec: {spec!r}")
    parts = urlsplit(raw_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"invalid upstream URL: {raw_url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return ProxyTarget(
        mount=mount,
        scheme=parts.scheme,
        host=parts.hostname,
        port=port,
        base_path=parts.path.rstrip("/"),
    )


def upstream_path(target: ProxyTarget, request_path: str, query: str) -> str:
    """Map an inbound request path onto the upstream path, preserving the query."""
    suffix = request_path[len(target.mount.rstrip("/")) :]
    path = (target.base_path + suffix) or "/"
    return f"{path}?{query}" if query else path


def filter_request_headers(
    headers: Dict[str, str], target: ProxyTarget, client_ip: str, scheme: str
) -> Dict[str, str]:
    """Strip hop-by-hop headers and set forwarding headers for the upstream."""
    forwarded = {
        name: value
        for name, value in headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS and name.lower() != "host"
    }
    forwarded["Host"] = target.authority
    existing = headers.get("x-forwarded-for")
    forwarded["X-Forwarded-For"] = f"{existing}, {client_ip}" if existing else client_ip
    forwarded["X-Forwarded-Proto"] = scheme
    forwarded["Via"] = "1.1 pyhttpd"
    return forwarded


def filter_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Strip hop-by-hop headers from an upstream response."""
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in HOP_BY_HOP_HEADERS
    }
