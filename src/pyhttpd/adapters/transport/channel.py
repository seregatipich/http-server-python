"""Adapter exposing a client socket as a domain Channel for upgraded protocols."""

import socket


class SocketChannel:
    """Wraps a client socket so an upgrade handler can own the raw stream."""

    def __init__(self, client_socket: socket.socket) -> None:
        self._socket = client_socket

    def read(self, size: int) -> bytes:
        """Read up to ``size`` bytes from the socket."""
        return self._socket.recv(size)

    def write(self, data: bytes) -> None:
        """Send all of ``data`` to the peer."""
        self._socket.sendall(data)

    def close(self) -> None:
        """Close the socket, ignoring an already-closed connection."""
        try:
            self._socket.close()
        except OSError:
            pass
