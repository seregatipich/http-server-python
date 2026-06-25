"""Pure helpers for HTTP caching validators and conditional requests."""

import hashlib
from dataclasses import dataclass
from email.utils import formatdate, parsedate_to_datetime
from typing import Mapping, Optional


@dataclass(frozen=True)
class FileMetadata:
    """Filesystem metadata used to build cache validators."""

    size: int
    mtime_ns: int
    content_type: str


def compute_etag(size: int, mtime_ns: int) -> str:
    """Return a quoted strong-ish ETag derived from size and mtime."""
    digest = hashlib.blake2b(f"{size}-{mtime_ns}".encode(), digest_size=16).hexdigest()
    return f'"{digest}"'


def http_date(epoch_seconds: float) -> str:
    """Format an epoch timestamp as an RFC 7231 GMT HTTP date."""
    return formatdate(epoch_seconds, usegmt=True)


def parse_http_date(value: str) -> Optional[float]:
    """Parse an HTTP date string into epoch seconds, or None if invalid."""
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None


def _normalize_etag(token: str) -> str:
    token = token.strip()
    if token.startswith("W/"):
        token = token[2:]
    return token


def _if_none_match(etag: str, header_value: str) -> bool:
    if header_value.strip() == "*":
        return True
    candidates = {_normalize_etag(item) for item in header_value.split(",")}
    return etag in candidates


def is_not_modified(
    etag: str, last_modified_epoch: float, request_headers: Mapping[str, str]
) -> bool:
    """Return whether the request's conditional headers permit a 304."""
    if "if-none-match" in request_headers:
        return _if_none_match(etag, request_headers["if-none-match"])
    if "if-modified-since" in request_headers:
        since = parse_http_date(request_headers["if-modified-since"])
        if since is not None:
            return last_modified_epoch <= since
    return False
