"""Backward-compatibility shim; socket/TLS factory now lives in adapters."""

from pyhttpd.adapters.tls import create_server_socket

__all__ = ["create_server_socket"]
