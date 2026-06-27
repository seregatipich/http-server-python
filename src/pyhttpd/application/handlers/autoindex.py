"""HTML directory listing for /files/* when autoindex is enabled.

Names are HTML-escaped and links URL-quoted to prevent stored XSS, and links are
absolute (derived from the request path) so they resolve with or without a
trailing slash. Listing never leaves the sandbox: the directory is already
resolved through ``resolve_sandbox_path`` before this handler runs.
"""

import html
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import quote

from pyhttpd.application.cors_headers import apply_cors_headers
from pyhttpd.domain import (
    FILES_ENDPOINT_PREFIX,
    SECURITY_HEADERS,
    CorsConfig,
    HttpRequest,
    HttpResponse,
    should_close,
)

Entry = Tuple[str, bool, int, float]


def render_autoindex(
    request: HttpRequest, resolved_path: Path, cors_config: Optional[CorsConfig]
) -> HttpResponse:
    """Render an HTML directory listing as a 200 response."""
    body = _render_html(request.path, _entries(resolved_path)).encode()
    headers = {"Content-Type": "text/html; charset=utf-8", **SECURITY_HEADERS}
    apply_cors_headers(headers, request, cors_config)
    return HttpResponse("HTTP/1.1 200 OK", headers, body, should_close(request.headers))


def _entries(resolved_path: Path) -> List[Entry]:
    items: List[Entry] = []
    with os.scandir(resolved_path) as scanner:
        for entry in scanner:
            try:
                stat_result = entry.stat()
            except OSError:
                continue
            items.append(
                (entry.name, entry.is_dir(), stat_result.st_size, stat_result.st_mtime)
            )
    items.sort(key=lambda item: (not item[1], item[0].lower()))
    return items


def _render_html(request_path: str, entries: List[Entry]) -> str:
    base = request_path.rstrip("/")
    rows = []
    if base != FILES_ENDPOINT_PREFIX.rstrip("/"):
        parent = base.rsplit("/", 1)[0] or FILES_ENDPOINT_PREFIX.rstrip("/")
        rows.append(f'<li><a href="{html.escape(parent)}/">../</a></li>')
    for name, is_dir, size, mtime in entries:
        suffix = "/" if is_dir else ""
        href = f"{base}/{quote(name)}{suffix}"
        label = html.escape(name) + suffix
        modified = datetime.fromtimestamp(mtime, timezone.utc).strftime(
            "%Y-%m-%d %H:%M"
        )
        size_text = "-" if is_dir else str(size)
        rows.append(
            f'<li><a href="{html.escape(href)}">{label}</a> '
            f"{size_text} {modified}</li>"
        )
    title = html.escape(request_path)
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>Index of {title}</title></head><body>"
        f"<h1>Index of {title}</h1><ul>{''.join(rows)}</ul></body></html>"
    )
