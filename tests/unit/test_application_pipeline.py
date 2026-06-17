"""Unit tests for the middleware onion-chain runner."""

# Fake middleware/handler doubles must match the chain signatures verbatim.
# pylint: disable=unused-argument

from pyhttpd.application import Handler, Middleware, RequestContext, build_chain
from pyhttpd.domain import HttpRequest, HttpResponse
from tests.unit._helpers import make_context, make_request


def make_response(status_line: str = "200 OK") -> HttpResponse:
    """Build a minimal HttpResponse for terminal handlers."""
    return HttpResponse(
        status_line=status_line, headers={}, body=b"", close_connection=False
    )


def recording_middleware(name: str, log: list[str]) -> Middleware:
    """Create a middleware that records enter/exit and delegates to next."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        log.append(f"enter:{name}")
        response = nxt(request, ctx)
        log.append(f"exit:{name}")
        return response

    return middleware


def short_circuit_middleware(
    name: str, log: list[str], result: HttpResponse
) -> Middleware:
    """Create a middleware that returns without calling next."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        log.append(f"short:{name}")
        return result

    return middleware


def test_handler_and_middleware_are_importable() -> None:
    """Handler and Middleware symbols are exported from the pipeline module."""
    assert Handler is not None
    assert Middleware is not None


def test_empty_chain_returns_terminal_directly() -> None:
    """With no middlewares the chain is the terminal handler itself."""
    terminal_response = make_response()

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        return terminal_response

    handler = build_chain([], terminal)
    result = handler(make_request(), make_context())

    assert result is terminal_response


def test_middlewares_run_outermost_first_then_terminal() -> None:
    """First middleware wraps the rest; terminal runs innermost."""
    log: list[str] = []

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        log.append("terminal")
        return make_response()

    handler = build_chain(
        [
            recording_middleware("a", log),
            recording_middleware("b", log),
            recording_middleware("c", log),
        ],
        terminal,
    )
    handler(make_request(), make_context())

    assert log == [
        "enter:a",
        "enter:b",
        "enter:c",
        "terminal",
        "exit:c",
        "exit:b",
        "exit:a",
    ]


def test_terminal_response_propagates_out_through_middlewares() -> None:
    """The terminal's return value is what the outer handler yields."""
    terminal_response = make_response("201 Created")
    log: list[str] = []

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        return terminal_response

    handler = build_chain(
        [recording_middleware("a", log), recording_middleware("b", log)],
        terminal,
    )
    result = handler(make_request(), make_context())

    assert result is terminal_response


def test_short_circuit_skips_inner_middlewares_and_terminal() -> None:
    """A middleware that omits next prevents deeper layers from running."""
    log: list[str] = []
    blocked = make_response("403 Forbidden")

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        log.append("terminal")
        return make_response()

    handler = build_chain(
        [
            recording_middleware("a", log),
            short_circuit_middleware("b", log, blocked),
            recording_middleware("c", log),
        ],
        terminal,
    )
    result = handler(make_request(), make_context())

    assert result is blocked
    assert log == ["enter:a", "short:b", "exit:a"]
    assert "enter:c" not in log
    assert "terminal" not in log


def test_outermost_short_circuit_skips_everything_else() -> None:
    """A short-circuit in the first middleware bypasses all later layers."""
    log: list[str] = []
    blocked = make_response("429 Too Many Requests")

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        log.append("terminal")
        return make_response()

    handler = build_chain(
        [
            short_circuit_middleware("a", log, blocked),
            recording_middleware("b", log),
        ],
        terminal,
    )
    result = handler(make_request(), make_context())

    assert result is blocked
    assert log == ["short:a"]


def test_request_and_context_thread_through_unchanged() -> None:
    """The same request and context instances reach the terminal handler."""
    request = make_request("/threaded")
    ctx = make_context()
    seen: dict[str, object] = {}

    def terminal(req: HttpRequest, context: RequestContext) -> HttpResponse:
        seen["request"] = req
        seen["ctx"] = context
        return make_response()

    handler = build_chain(
        [recording_middleware("a", []), recording_middleware("b", [])],
        terminal,
    )
    handler(request, ctx)

    assert seen["request"] is request
    assert seen["ctx"] is ctx


def test_middleware_can_mutate_context_for_inner_layers() -> None:
    """Context mutations by an outer middleware are visible to the terminal."""

    def tagging_middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        ctx.correlation_id = "rewritten"
        return nxt(request, ctx)

    observed: dict[str, object] = {}

    def terminal(req: HttpRequest, ctx: RequestContext) -> HttpResponse:
        observed["correlation_id"] = ctx.correlation_id
        return make_response()

    handler = build_chain([tagging_middleware], terminal)
    handler(make_request(), make_context())

    assert observed["correlation_id"] == "rewritten"


def test_chain_consumes_iterable_only_once_at_build_time() -> None:
    """A one-shot iterable of middlewares is materialized during build."""
    log: list[str] = []

    def terminal(request: HttpRequest, ctx: RequestContext) -> HttpResponse:
        return make_response()

    middlewares = iter([recording_middleware("a", log), recording_middleware("b", log)])
    handler = build_chain(middlewares, terminal)

    handler(make_request(), make_context())
    handler(make_request(), make_context())

    assert log == [
        "enter:a",
        "enter:b",
        "exit:b",
        "exit:a",
        "enter:a",
        "enter:b",
        "exit:b",
        "exit:a",
    ]
