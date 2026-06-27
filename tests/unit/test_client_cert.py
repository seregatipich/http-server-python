"""Unit tests for mutual-TLS client-cert authentication (F12)."""

import pytest

from pyhttpd.adapters.auth.client_cert import (
    ClientCertAuthenticator,
    principal_from_peercert,
)
from pyhttpd.adapters.tls import _parse_sni_spec
from pyhttpd.application import RequestContext
from pyhttpd.application.middleware.auth import make_auth_middleware
from pyhttpd.domain import AuthConfig, Forbidden, Principal
from tests.unit._helpers import PASSTHROUGH, RecordingLogger, make_request


def test_principal_from_peercert_uses_common_name() -> None:
    peercert = {"subject": ((("commonName", "writer"),),)}
    principal = principal_from_peercert(peercert, {"writer": ["files:write"]})
    assert principal is not None
    assert principal.identity == "writer"
    assert principal.has_scope("files:write")


def test_principal_from_peercert_falls_back_to_dns_san() -> None:
    peercert = {"subject": (), "subjectAltName": (("DNS", "svc.local"),)}
    principal = principal_from_peercert(peercert, {})
    assert principal is not None
    assert principal.identity == "svc.local"
    assert principal.scopes == frozenset()


def test_principal_from_peercert_none_without_certificate() -> None:
    assert principal_from_peercert(None, {}) is None
    assert principal_from_peercert({}, {}) is None


def test_principal_from_peercert_none_without_identity() -> None:
    assert principal_from_peercert({"subject": ()}, {}) is None


def test_client_cert_authenticator_defers_to_transport() -> None:
    authenticator = ClientCertAuthenticator(AuthConfig(mode="client-cert"))
    assert authenticator.challenge == "ClientCert"
    assert authenticator.authenticate({"authorization": "Bearer x"}) is None


class _NullAuthenticator:
    challenge = "ClientCert"

    def authenticate(self, _headers):
        return None


def _context_with_principal(principal: Principal) -> RequestContext:
    return RequestContext(correlation_id=None, start_ns=0, client_principal=principal)


def test_auth_middleware_authorizes_via_client_principal() -> None:
    middleware = make_auth_middleware(_NullAuthenticator(), RecordingLogger())
    ctx = _context_with_principal(Principal("writer", frozenset({"files:write"})))
    result = middleware(
        make_request(path="/files/x", method="POST"), ctx, lambda *_: PASSTHROUGH
    )
    assert result is PASSTHROUGH


def test_auth_middleware_forbids_client_principal_without_scope() -> None:
    middleware = make_auth_middleware(_NullAuthenticator(), RecordingLogger())
    ctx = _context_with_principal(Principal("reader", frozenset({"files:read"})))
    with pytest.raises(Forbidden):
        middleware(make_request(path="/files/x", method="POST"), ctx, lambda *_: None)


def test_parse_sni_spec_splits_host_cert_key() -> None:
    assert _parse_sni_spec("a.test:/c.pem:/k.pem") == ("a.test", "/c.pem", "/k.pem")


def test_parse_sni_spec_rejects_incomplete() -> None:
    with pytest.raises(ValueError):
        _parse_sni_spec("a.test:/c.pem")
