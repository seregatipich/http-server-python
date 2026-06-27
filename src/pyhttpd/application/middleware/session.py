"""Session middleware: hydrate an existing session or issue a signed cookie."""

from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from typing import Optional

from pyhttpd.application.context import RequestContext
from pyhttpd.application.pipeline import Handler, Middleware
from pyhttpd.domain import HttpRequest, HttpResponse, SessionStore
from pyhttpd.domain.sessions import sign, verify

SESSION_COOKIE_NAME = "session"


@dataclass(frozen=True)
class SessionCookiePolicy:
    """Attributes applied to the issued Set-Cookie header."""

    secret: str
    ttl_seconds: int
    secure: bool = False
    same_site: str = "Lax"


def make_session_middleware(
    store: SessionStore, policy: SessionCookiePolicy
) -> Middleware:
    """Build middleware that attaches a session and issues its cookie."""

    def middleware(
        request: HttpRequest, ctx: RequestContext, nxt: Handler
    ) -> HttpResponse:
        cookie_session_id = _verified_cookie_session_id(request, policy.secret)
        data = store.get(cookie_session_id) if cookie_session_id else None
        if data is not None:
            ctx.session = data
            return nxt(request, ctx)
        new_session_id = store.create()
        ctx.session = store.get(new_session_id)
        response = nxt(request, ctx)
        response.headers["Set-Cookie"] = _cookie_header(new_session_id, policy)
        return response

    return middleware


def _verified_cookie_session_id(request: HttpRequest, secret: str) -> Optional[str]:
    header = request.headers.get("cookie", "")
    if not header:
        return None
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(header)
    except CookieError:
        return None
    morsel = jar.get(SESSION_COOKIE_NAME)
    if morsel is None:
        return None
    return verify(morsel.value, secret)


def _cookie_header(session_id: str, policy: SessionCookiePolicy) -> str:
    attributes = [
        f"{SESSION_COOKIE_NAME}={sign(session_id, policy.secret)}",
        "Path=/",
        "HttpOnly",
        f"SameSite={policy.same_site}",
        f"Max-Age={policy.ttl_seconds}",
    ]
    if policy.secure:
        attributes.append("Secure")
    return "; ".join(attributes)
