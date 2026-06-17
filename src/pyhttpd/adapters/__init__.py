"""Infrastructure adapters bridging the domain to external systems."""

from pyhttpd.adapters.clock import MonotonicClock
from pyhttpd.adapters.ids import Uuid4IdGenerator
from pyhttpd.adapters.lifecycle import ServerLifecycle
from pyhttpd.adapters.tls import create_server_socket

__all__ = [
    "MonotonicClock",
    "Uuid4IdGenerator",
    "ServerLifecycle",
    "create_server_socket",
]
