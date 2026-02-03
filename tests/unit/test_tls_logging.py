"""Unit tests for TLS logging events."""

import logging
import ssl
from unittest.mock import MagicMock, patch

from server.bootstrap.socket_factory import create_server_socket


def test_create_server_socket_logs_tls_error(caplog):
    """Verify that TLS errors during socket creation are logged as CRITICAL."""
    caplog.set_level(logging.CRITICAL)

    mock_args = MagicMock()
    mock_args.host = "localhost"
    mock_args.port = 8443
    mock_args.cert = "fake_cert.pem"
    mock_args.key = "fake_key.pem"

    with patch(
        "server.bootstrap.socket_factory.socket.create_server"
    ) as mock_create_server, patch(
        "server.bootstrap.socket_factory.ssl.SSLContext"
    ) as mock_ssl_context, patch(
        "server.bootstrap.socket_factory.sys.exit"
    ) as mock_exit:

        mock_server_sock = MagicMock()
        mock_create_server.return_value = mock_server_sock

        # Simulate SSLError when loading cert chain
        context_instance = MagicMock()
        context_instance.load_cert_chain.side_effect = ssl.SSLError(
            "Invalid certificate"
        )
        mock_ssl_context.return_value = context_instance

        create_server_socket(mock_args)

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
