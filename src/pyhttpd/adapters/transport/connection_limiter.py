"""Connection concurrency limiting logic."""

import threading
from typing import Optional


class ConnectionLimiter:
    """Enforces global and per-IP concurrent connection quotas."""

    def __init__(self, max_connections: int, max_connections_per_ip: int) -> None:
        self._max_connections = max(0, max_connections)
        self._max_connections_per_ip = max(0, max_connections_per_ip)
        self._lock = threading.Lock()
        self._global_active = 0
        self._per_ip: dict[str, int] = {}

    def acquire(self, client_ip: str) -> tuple[bool, Optional[str]]:
        """Attempt to register a new connection for the given client IP."""

        with self._lock:
            per_ip_active = self._per_ip.get(client_ip, 0)
            if (
                self._max_connections_per_ip
                and per_ip_active >= self._max_connections_per_ip
            ):
                return False, "ip"
            if self._max_connections and self._global_active >= self._max_connections:
                return False, "global"
            self._global_active += 1
            self._per_ip[client_ip] = per_ip_active + 1
            return True, None

    def release(self, client_ip: str) -> None:
        """Release a previously acquired connection slot."""

        with self._lock:
            if self._global_active > 0:
                self._global_active -= 1
            per_ip_active = self._per_ip.get(client_ip, 0)
            if per_ip_active <= 1:
                self._per_ip.pop(client_ip, None)
            else:
                self._per_ip[client_ip] = per_ip_active - 1
