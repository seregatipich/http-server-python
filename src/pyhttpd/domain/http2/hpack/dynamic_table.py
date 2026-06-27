"""HPACK dynamic table (RFC 7541 sections 2.3.2 and 4)."""

from collections import deque
from typing import Deque, Tuple

ENTRY_OVERHEAD = 32


class DynamicTable:
    """FIFO header table bounded by an octet budget; newest entry is index 0."""

    def __init__(self, max_size: int = 4096) -> None:
        self._max_size = max_size
        self._size = 0
        self._entries: Deque[Tuple[str, str]] = deque()

    def add(self, name: str, value: str) -> None:
        """Insert a header, evicting oldest entries to honor the size budget."""
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        while self._size + entry_size > self._max_size and self._entries:
            self._evict_oldest()
        if entry_size > self._max_size:
            return
        self._entries.appendleft((name, value))
        self._size += entry_size

    def get(self, index: int) -> Tuple[str, str]:
        """Return the entry at a zero-based index (0 = most recently added)."""
        return self._entries[index]

    def resize(self, new_max_size: int) -> None:
        """Apply a dynamic table size update, evicting as needed."""
        self._max_size = new_max_size
        while self._size > self._max_size and self._entries:
            self._evict_oldest()

    def __len__(self) -> int:
        return len(self._entries)

    def _evict_oldest(self) -> None:
        name, value = self._entries.pop()
        self._size -= len(name) + len(value) + ENTRY_OVERHEAD
