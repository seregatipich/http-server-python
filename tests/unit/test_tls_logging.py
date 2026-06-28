"""Unit tests for TLS logging events."""

import logging
import ssl
from unittest.mock import MagicMock, patch

from pyhttpd.adapters.tls import build_tls_context


def test_build_tls_context_logs_tls_error(caplog):
    """Verify that TLS errors while building the context are logged as CRITICAL."""
    caplog.set_level(logging.CRITICAL)

    mock_args = MagicMock()
    mock_args.host = "localhost"
    mock_args.port = 8443
    mock_args.cert = "fake_cert.pem"
    mock_args.key = "fake_key.pem"

    with (
        patch("pyhttpd.adapters.tls.ssl.SSLContext") as mock_ssl_context,
        patch("pyhttpd.adapters.tls.sys.exit") as mock_exit,
    ):

        # Simulate SSLError when loading cert chain
        context_instance = MagicMock()
        context_instance.load_cert_chain.side_effect = ssl.SSLError(
            "Invalid certificate"
        )
        mock_ssl_context.return_value = context_instance

        build_tls_context(mock_args)

        # Verify exit was called
        mock_exit.assert_called_with(1)

    # Verify log record
    critical_record = next(
        (r for r in caplog.records if r.levelno == logging.CRITICAL), None
    )
    assert critical_record is not None
    assert "Failed to load TLS certificates" in critical_record.message
    # SSLError string representation can be a tuple string like "('Invalid certificate',)"
    assert "Invalid certificate" in str(getattr(critical_record, "error", ""))
