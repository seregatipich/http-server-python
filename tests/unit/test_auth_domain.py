"""Unit tests for the authentication domain primitives."""

import pytest

from pyhttpd.domain import (
    DEFAULT_AUTH_MODE,
    AuthConfig,
    HttpError,
    Principal,
    Unauthorized,
    required_scope,
)


def test_unauthorized_is_a_401_carrying_a_challenge():
    """Unauthorized reports a 401 status line and stores its challenge."""
    error = Unauthorized('Bearer realm="pyhttpd"')
    assert error.status == 401
    assert error.reason == "Unauthorized"
    assert error.status_line == "HTTP/1.1 401 Unauthorized"
    assert error.challenge == 'Bearer realm="pyhttpd"'


def test_unauthorized_is_an_http_error():
    """Unauthorized is catchable through the HttpError base."""
    with pytest.raises(HttpError):
        raise Unauthorized('ApiKey realm="pyhttpd"')


def test_principal_has_scope_checks_membership():
    """A principal reports the scopes it was granted and nothing else."""
    principal = Principal(identity="reader", scopes=frozenset({"files:read"}))
    assert principal.has_scope("files:read")
    assert not principal.has_scope("files:write")


def test_principal_is_frozen():
    """Principal is an immutable value object."""
    principal = Principal(identity="reader", scopes=frozenset())
    with pytest.raises(AttributeError):
        principal.identity = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "path, method, expected",
    [
        ("/files/report.txt", "GET", "files:read"),
        ("/files/report.txt", "HEAD", "files:read"),
        ("/files/report.txt", "POST", "files:write"),
        ("/files/report.txt", "PUT", "files:write"),
        ("/files/report.txt", "DELETE", "files:write"),
        ("/files", "GET", "files:read"),
        ("/files/", "POST", "files:write"),
        ("/healthz", "GET", None),
        ("/", "GET", None),
        ("/filesystem", "GET", None),
    ],
)
def test_required_scope_maps_path_and_method(path, method, expected):
    """The RBAC table gates /files reads (GET/HEAD) and writes (POST/PUT/DELETE)."""
    assert required_scope(path, method) == expected


def test_auth_config_defaults():
    """AuthConfig carries auth settings with sensible optional defaults."""
    config = AuthConfig(
        mode="api-key",
        credentials={"reader": "abc123"},
        roles={"reader": ["files:read"]},
    )
    assert config.mode == "api-key"
    assert config.credentials == {"reader": "abc123"}
    assert config.roles == {"reader": ["files:read"]}
    assert config.jwt_secret == ""
    assert config.jwt_issuer is None
    assert config.jwt_audience is None


def test_default_auth_mode_is_none():
    """Auth is disabled unless explicitly configured."""
    assert DEFAULT_AUTH_MODE == "none"
