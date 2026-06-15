"""Middleware protocol and onion chain runner."""

from typing import Callable, Iterable, Protocol

from pyhttpd.application.context import RequestContext
from pyhttpd.domain.http import HttpRequest, HttpResponse

Handler = Callable[[HttpRequest, RequestContext], HttpResponse]


class Middleware(Protocol):
    """A layer that may act before and after delegating to the next handler."""

    def __call__(
        self, request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse: ...


def build_chain(middlewares: Iterable[Middleware], terminal: Handler) -> Handler:
    """Fold middlewares right-to-left; middlewares[0] is outermost."""
    handler = terminal
    for middleware in reversed(list(middlewares)):

        def make(mw: Middleware, nxt: Handler) -> Handler:
            def call(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
                return mw(request, ctx, nxt)

            return call

        handler = make(middleware, handler)
    return handler
