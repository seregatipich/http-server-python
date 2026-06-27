"""Buffered frame reader shared by the WebSocket and HTTP/2 drivers.

Wraps a Channel and a frame-decode callable, refilling from the channel until a
complete frame is available. Lives in the application layer so both the
application-level WebSocket driver and the transport-level HTTP/2 driver can
reuse it without crossing layer boundaries.
"""

from typing import Callable, Generic, Optional, Tuple, TypeVar

from pyhttpd.domain import Channel

T = TypeVar("T")


class BufferedFrameReader(Generic[T]):
    """Yields decoded frames from a Channel, refilling the buffer as needed."""

    def __init__(
        self,
        channel: Channel,
        decode: Callable[[bytes], Optional[Tuple[T, int]]],
        read_size: int = 65536,
        initial: bytes = b"",
    ) -> None:
        self._channel = channel
        self._decode = decode
        self._read_size = read_size
        self._buffer = bytearray(initial)

    def next_frame(self) -> Optional[T]:
        """Return the next complete frame, or None when the peer disconnects."""
        while True:
            decoded = self._decode(bytes(self._buffer))
            if decoded is not None:
                frame, consumed = decoded
                del self._buffer[:consumed]
                return frame
            if not self._fill():
                return None

    def read_exact(self, count: int) -> Optional[bytes]:
        """Return exactly ``count`` bytes (for fixed prefixes), or None on EOF."""
        while len(self._buffer) < count:
            if not self._fill():
                return None
        taken = bytes(self._buffer[:count])
        del self._buffer[:count]
        return taken

    def _fill(self) -> bool:
        chunk = self._channel.read(self._read_size)
        if not chunk:
            return False
        self._buffer.extend(chunk)
        return True
