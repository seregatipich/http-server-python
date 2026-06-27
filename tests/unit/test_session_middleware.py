"""Unit tests for the session middleware (F4)."""

from pyhttpd.adapters.session.store import InMemorySessionStore
from pyhttpd.application.middleware.session import (
    SESSION_COOKIE_NAME,
    SessionCookiePolicy,
    make_session_middleware,
)
from pyhttpd.domain import HttpResponse
from pyhttpd.domain.sessions import sign
from tests.unit._helpers import make_context, make_request

POLICY = SessionCookiePolicy(secret="s3cr3t", ttl_seconds=60)


def _terminal(_request, _ctx) -> HttpResponse:
    return HttpResponse("HTTP/1.1 200 OK", {}, b"ok", False)


def test_new_session_attaches_data_and_sets_cookie() -> None:
    store = InMemorySessionStore(ttl_seconds=60)
    middleware = make_session_middleware(store, POLICY)
    ctx = make_context()

    response = middleware(make_request(), ctx, _terminal)

    assert ctx.session == {}
    cookie = response.headers["Set-Cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE_NAME}=")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_existing_session_is_hydrated_without_new_cookie() -> None:
    store = InMemorySessionStore(ttl_seconds=60)
    session_id = store.create()
    stored = store.get(session_id)
    assert stored is not None
    stored["count"] = 7
    token = sign(session_id, POLICY.secret)
    middleware = make_session_middleware(store, POLICY)
    ctx = make_context()

    request = make_request(headers={"cookie": f"{SESSION_COOKIE_NAME}={token}"})
    response = middleware(request, ctx, _terminal)

    assert ctx.session == {"count": 7}
    assert "Set-Cookie" not in response.headers


def test_tampered_cookie_starts_a_fresh_session() -> None:
    store = InMemorySessionStore(ttl_seconds=60)
    middleware = make_session_middleware(store, POLICY)
    ctx = make_context()

    request = make_request(headers={"cookie": f"{SESSION_COOKIE_NAME}=forged.sig"})
    response = middleware(request, ctx, _terminal)

    assert ctx.session == {}
    assert "Set-Cookie" in response.headers


def test_secure_and_samesite_strict_attributes() -> None:
    store = InMemorySessionStore(ttl_seconds=60)
    policy = SessionCookiePolicy(
        secret="s3cr3t", ttl_seconds=60, secure=True, same_site="Strict"
    )
    middleware = make_session_middleware(store, policy)

    response = middleware(make_request(), make_context(), _terminal)

    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie
