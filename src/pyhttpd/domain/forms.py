"""Pure parsers for query strings and form-encoded request bodies.

Handlers call these lazily on a request; parsing never runs automatically, so
endpoints that do not consume form data pay no cost and expose no attack
surface. Field and part counts are capped to defuse parser-bomb inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as DEFAULT_EMAIL_POLICY
from typing import Optional
from urllib.parse import parse_qsl

DEFAULT_MAX_FIELDS = 1000


@dataclass(frozen=True)
class FormPart:
    """A single part of a parsed multipart/form-data body."""

    name: str
    filename: Optional[str]
    content_type: str
    content: bytes


def parse_query(
    query: str, max_fields: int = DEFAULT_MAX_FIELDS
) -> dict[str, list[str]]:
    """Parse a URL query string into a multi-valued mapping."""
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=max_fields)
    return _group(pairs)


def parse_urlencoded(
    body: bytes, max_fields: int = DEFAULT_MAX_FIELDS
) -> dict[str, list[str]]:
    """Parse an application/x-www-form-urlencoded body into a mapping."""
    text = body.decode("utf-8")
    pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=max_fields)
    return _group(pairs)


def parse_multipart(
    body: bytes, content_type: str, max_parts: int = DEFAULT_MAX_FIELDS
) -> list[FormPart]:
    """Parse a multipart/form-data body into its constituent parts."""
    if "multipart/" not in content_type.lower():
        raise ValueError("not a multipart content type")
    prologue = (
        b"Content-Type: " + content_type.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n"
    )
    message = BytesParser(policy=DEFAULT_EMAIL_POLICY).parsebytes(prologue + body)
    if not message.is_multipart():
        raise ValueError("malformed multipart body")
    parts: list[FormPart] = []
    for part in message.iter_parts():
        if len(parts) >= max_parts:
            raise ValueError("too many multipart parts")
        raw_name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True)
        parts.append(
            FormPart(
                name=raw_name if isinstance(raw_name, str) else "",
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                content=payload if isinstance(payload, bytes) else b"",
            )
        )
    return parts


def _group(pairs: list[tuple[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for key, value in pairs:
        grouped.setdefault(key, []).append(value)
    return grouped
