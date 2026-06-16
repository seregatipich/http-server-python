"""Request validation middleware for the application pipeline."""

from typing import AbstractSet

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import (
    BadRequest,
    Forbidden,
    HttpRequest,
    HttpResponse,
    MethodNotAllowed,
    RequestEntityTooLarge,
)


def _enforce_allowed_method(
    request: HttpRequest, allowed_methods: AbstractSet[str]
) -> None:
    if request.method not in allowed_methods:
        raise MethodNotAllowed(allowed_methods)


def _enforce_safe_path(request: HttpRequest) -> None:
    if not request.path.startswith("/") or "\x00" in request.path:
        raise BadRequest("malformed request path")
    if (
        "/../" in request.path
        or request.path.endswith("/..")
        or request.path.startswith("/..")
    ):
        raise Forbidden("path traversal rejected")


def _enforce_post_constraints(request: HttpRequest, max_body_bytes: int) -> None:
    declared_length = request.headers.get("content-length")
    if declared_length is None:
        raise BadRequest("missing Content-Length")
    try:
        content_length = int(declared_length)
    except ValueError as exc:
        raise BadRequest("invalid Content-Length") from exc
    if content_length != len(request.body):
        raise BadRequest("Content-Length mismatch")
    if content_length > max_body_bytes:
        raise RequestEntityTooLarge("request body exceeds limit")


def make_validation_middleware(
    allowed_methods: AbstractSet[str],
    max_body_bytes: int,
) -> Middleware:
    """Build middleware that rejects invalid requests with typed errors."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        _enforce_allowed_method(request, allowed_methods)
        _enforce_safe_path(request)
        if request.method == "POST":
            _enforce_post_constraints(request, max_body_bytes)
        return nxt(request, ctx)

    return middleware
