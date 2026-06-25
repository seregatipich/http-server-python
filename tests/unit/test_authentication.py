"""Unit tests for the authentication/authorization middleware."""

import logging

import pytest

from pyhttpd.application import build_chain, make_auth_middleware
from pyhttpd.domain import Forbidden, HttpResponse, Principal, Unauthorized
from tests.unit._helpers import RecordingLogger, make_context, make_request


class StubAuthenticator:
    """Authenticator double returning a preconfigured principal."""

    challenge = 'ApiKey realm="pyhttpd"'

    def __init__(self, principal):
        self.principal = principal
        self.calls = 0

    def authenticate(self, headers):
        """Return the configured principal, counting invocations."""
        self.calls += 1
        return self.principal


def _terminal(log):
    def terminal(request, ctx):
        log.append("terminal")
        return HttpResponse("HTTP/1.1 200 OK", {}, b"", close_connection=False)

    return terminal


def _chain(authenticator, logger, log):
    return build_chain([make_auth_middleware(authenticator, logger)], _terminal(log))


def test_missing_credentials_raise_unauthorized_and_skip_terminal():
    """An unauthenticated request raises 401 and never reaches the handler."""
    log: list[str] = []
    logger = RecordingLogger()
    handler = _chain(StubAuthenticator(None), logger, log)

    with pytest.raises(Unauthorized) as caught:
        handler(make_request("/files/secret.txt"), make_context())

    assert caught.value.challenge == 'ApiKey realm="pyhttpd"'
    assert "terminal" not in log
    assert (logging.WARNING, "auth_unauthenticated") in [
        (level, event) for level, event, _ in logger.events
    ]


def test_authorized_principal_passes_through_and_sets_context():
    """A principal with the required scope reaches the handler and is recorded."""
    log: list[str] = []
    principal = Principal(identity="reader", scopes=frozenset({"files:read"}))
    handler = _chain(StubAuthenticator(principal), RecordingLogger(), log)
    ctx = make_context()

    handler(make_request("/files/report.txt"), ctx)

    assert log == ["terminal"]
    assert ctx.principal == "reader"


def test_authenticated_but_underprivileged_raises_forbidden():
    """A principal lacking the required scope is rejected with 403."""
    log: list[str] = []
    logger = RecordingLogger()
    principal = Principal(identity="reader", scopes=frozenset({"files:read"}))
    handler = _chain(StubAuthenticator(principal), logger, log)

    with pytest.raises(Forbidden):
        handler(make_request("/files/report.txt", method="POST"), make_context())

    assert "terminal" not in log
    assert (logging.WARNING, "auth_forbidden") in [
        (level, event) for level, event, _ in logger.events
    ]


def test_healthz_bypasses_authentication():
    """The health endpoint is reachable without credentials."""
    log: list[str] = []
    authenticator = StubAuthenticator(None)
    handler = _chain(authenticator, RecordingLogger(), log)

    handler(make_request("/healthz"), make_context())

    assert log == ["terminal"]
    assert authenticator.calls == 0


def test_cors_preflight_bypasses_authentication():
    """A CORS preflight OPTIONS request is not authenticated."""
    log: list[str] = []
    authenticator = StubAuthenticator(None)
    handler = _chain(authenticator, RecordingLogger(), log)
    preflight = make_request(
        "/files/report.txt",
        method="OPTIONS",
        headers={"access-control-request-method": "GET"},
    )

    handler(preflight, make_context())

    assert log == ["terminal"]
    assert authenticator.calls == 0


def test_open_path_allows_any_authenticated_principal():
    """A path with no required scope admits any authenticated principal."""
    log: list[str] = []
    principal = Principal(identity="anyone", scopes=frozenset())
    handler = _chain(StubAuthenticator(principal), RecordingLogger(), log)
    ctx = make_context()

    handler(make_request("/user-agent"), ctx)

    assert log == ["terminal"]
    assert ctx.principal == "anyone"
