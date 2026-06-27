"""Authentication and authorization middleware."""

import logging

from pyhttpd.application.context import RequestContext
from pyhttpd.application.cors_headers import is_preflight_request
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import (
    Authenticator,
    Forbidden,
    HttpRequest,
    HttpResponse,
    Logger,
    Unauthorized,
    required_scope,
)

_PUBLIC_PATHS = frozenset({"/healthz"})


def make_auth_middleware(authenticator: Authenticator, logger: Logger) -> Middleware:
    """Build middleware enforcing authentication and scope-based access."""
    challenge = authenticator.challenge

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        if request.path in _PUBLIC_PATHS or is_preflight_request(request):
            return nxt(request, ctx)

        principal = ctx.client_principal or authenticator.authenticate(request.headers)
        if principal is None:
            logger.log(
                logging.WARNING,
                "auth_unauthenticated",
                path=request.path,
                method=request.method,
            )
            raise Unauthorized(challenge)

        needed = required_scope(request.path, request.method)
        if needed is not None and not principal.has_scope(needed):
            logger.log(
                logging.WARNING,
                "auth_forbidden",
                identity=principal.identity,
                required_scope=needed,
            )
            raise Forbidden()

        ctx.principal = principal.identity
        return nxt(request, ctx)

    return middleware
