"""Thread-safe in-memory session store with TTL and capacity eviction."""

import secrets
import threading
import time
from typing import Callable, Dict, Optional, Tuple


class InMemorySessionStore:
    """Maps signed session ids to mutable data, evicting on TTL and capacity.

    The same data dict is handed back on every ``get`` so handler mutations
    persist for the session's lifetime. Suitable for a single process; sessions
    do not survive a restart and are not shared across processes.
    """

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int = 10_000,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._now = now
        self._lock = threading.Lock()
        self._sessions: Dict[str, Tuple[Dict[str, object], float]] = {}

    def create(self) -> str:
        """Create an empty session and return its identifier."""
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._prune_locked()
            self._sessions[session_id] = ({}, self._now() + self._ttl)
        return session_id

    def get(self, session_id: str) -> Optional[Dict[str, object]]:
        """Return the session data if present and unexpired, refreshing its TTL."""
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                return None
            data, expiry = entry
            if self._now() >= expiry:
                del self._sessions[session_id]
                return None
            self._sessions[session_id] = (data, self._now() + self._ttl)
            return data

    def _prune_locked(self) -> None:
        now = self._now()
        expired = [sid for sid, (_, expiry) in self._sessions.items() if now >= expiry]
        for session_id in expired:
            del self._sessions[session_id]
        if len(self._sessions) >= self._max_entries:
            oldest = min(self._sessions, key=lambda sid: self._sessions[sid][1])
            del self._sessions[oldest]
