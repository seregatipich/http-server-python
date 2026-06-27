"""Assembles the per-request handler chain wired for a worker connection.

Owns the wiring of the default router, the optional reverse-proxy dispatch, the
application middleware chain, and the optional session middleware, keeping that
fan-out out of the worker's connection-lifecycle module.
"""

from pyhttpd.adapters.proxy import forward
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.worker_logging import WORKER_PORT_LOGGER
from pyhttpd.application.context import RequestContext
from pyhttpd.application.handlers.proxy import make_proxy_dispatch
from pyhttpd.application.middleware.assembly import build_request_chain
from pyhttpd.application.middleware.session import make_session_middleware
from pyhttpd.application.pipeline import Handler
from pyhttpd.application.routing import make_default_router
from pyhttpd.domain import HttpRequest, HttpResponse


def build_worker_chain(
    context: WorkerContext, client_ip: str, max_body_bytes: int
) -> Handler:
    """Assemble the application middleware chain over the default router."""
    router = make_default_router(
        context.directory,
        context.lifecycle,
        WORKER_PORT_LOGGER,
        context.cors_config,
        context.metrics_sink,
        context.file_options,
        context.enable_sse,
        context.enable_websocket,
    )
    dispatch = _wrap_with_proxy(router.dispatch, context, client_ip)
    chain = build_request_chain(
        dispatch,
        cors_config=context.cors_config,
        metrics_sink=context.metrics_sink,
        rate_limiter=context.rate_limiter,
        authenticator=context.authenticator,
        logger=WORKER_PORT_LOGGER,
        client_ip=client_ip,
        max_body_bytes=max_body_bytes,
    )
    return _wrap_with_session(chain, context)


def _wrap_with_proxy(
    dispatch: Handler, context: WorkerContext, client_ip: str
) -> Handler:
    if not context.proxy_targets:
        return dispatch
    return make_proxy_dispatch(
        context.proxy_targets,
        forward,
        client_ip,
        context.proxy_timeout,
        WORKER_PORT_LOGGER,
        dispatch,
    )


def _wrap_with_session(chain: Handler, context: WorkerContext) -> Handler:
    if context.session_store is None or context.session_policy is None:
        return chain
    session_middleware = make_session_middleware(
        context.session_store, context.session_policy
    )

    def with_session(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        return session_middleware(request, ctx, chain)

    return with_session
