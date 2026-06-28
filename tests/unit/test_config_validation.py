"""Unit tests for fail-fast startup configuration validation."""

from pyhttpd.adapters.config import parse_cli_args
from pyhttpd.application.config_validation import validate_startup_config


def _args(tmp_path, extra=None):
    argv = ["--directory", str(tmp_path), "--port", "8080"]
    if extra:
        argv.extend(extra)
    return parse_cli_args(argv)


def test_default_configuration_is_valid(tmp_path):
    """A default argument set produces no validation errors."""
    assert validate_startup_config(_args(tmp_path)) == []


def test_negative_timeout_is_rejected(tmp_path):
    """A non-positive socket timeout is reported."""
    errors = validate_startup_config(_args(tmp_path, ["--socket-timeout", "0"]))
    assert any("timeout" in error.lower() for error in errors)


def test_invalid_port_is_rejected(tmp_path):
    """A port outside the valid range is reported."""
    errors = validate_startup_config(_args(tmp_path, ["--port", "70000"]))
    assert any("port" in error.lower() for error in errors)


def test_tls_requires_both_cert_and_key(tmp_path):
    """Supplying only a certificate (no key) is reported."""
    cert = tmp_path / "cert.pem"
    cert.write_text("x")
    errors = validate_startup_config(_args(tmp_path, ["--cert", str(cert)]))
    assert any("key" in error.lower() for error in errors)


def test_tls_unreadable_files_are_reported(tmp_path):
    """Missing TLS files are reported as unreadable."""
    errors = validate_startup_config(
        _args(tmp_path, ["--cert", "/nope/cert.pem", "--key", "/nope/key.pem"])
    )
    assert any("readable" in error.lower() for error in errors)


def test_api_key_mode_requires_credentials(tmp_path):
    """Api-key auth without credentials is reported."""
    errors = validate_startup_config(_args(tmp_path, ["--auth-mode", "api-key"]))
    assert any("credential" in error.lower() for error in errors)


def test_jwt_mode_requires_secret(tmp_path):
    """JWT auth without a secret is reported."""
    errors = validate_startup_config(_args(tmp_path, ["--auth-mode", "jwt"]))
    assert any("secret" in error.lower() for error in errors)


def _tls_pair(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("x")
    key.write_text("x")
    return ["--cert", str(cert), "--key", str(key)]


def test_require_client_cert_without_ca_is_rejected(tmp_path):
    """Requiring a client cert without a CA bundle would fail open and is rejected."""
    errors = validate_startup_config(
        _args(tmp_path, _tls_pair(tmp_path) + ["--tls-require-client-cert"])
    )
    assert any("tls-client-ca" in error.lower() for error in errors)


def test_client_ca_without_cert_and_key_is_rejected(tmp_path):
    """mTLS verification flags without server TLS would run plaintext and are rejected."""
    errors = validate_startup_config(
        _args(tmp_path, ["--tls-client-ca", "/etc/ssl/ca.pem"])
    )
    assert any("--cert" in error and "--key" in error for error in errors)


def test_require_client_cert_without_cert_and_key_is_rejected(tmp_path):
    """Requiring a client cert without server TLS would run plaintext and is rejected."""
    errors = validate_startup_config(_args(tmp_path, ["--tls-require-client-cert"]))
    assert any("--cert" in error and "--key" in error for error in errors)


def test_tls_sni_without_cert_and_key_is_rejected(tmp_path):
    """An SNI certificate map without base TLS would run plaintext and is rejected."""
    errors = validate_startup_config(
        _args(tmp_path, ["--tls-sni", "example.com:/c.pem:/k.pem"])
    )
    assert any("--cert" in error and "--key" in error for error in errors)


def test_full_mtls_configuration_is_valid(tmp_path):
    """A complete mTLS configuration (cert, key, CA, require) is accepted."""
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    errors = validate_startup_config(
        _args(
            tmp_path,
            _tls_pair(tmp_path)
            + ["--tls-client-ca", str(ca), "--tls-require-client-cert"],
        )
    )
    assert errors == []
