"""Server lifecycle state management."""

import logging
import threading
import time

LIFECYCLE_LOGGER = logging.getLogger("http_server.lifecycle")


class ServerLifecycle:
    """Manages server lifecycle state and worker thread tracking."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._draining_event = threading.Event()
        self._workers: set[threading.Thread] = set()

    def should_stop(self) -> bool:
        """Check if the server should stop accepting new connections."""
        return self._stop_event.is_set()

    def is_draining(self) -> bool:
        """Check if the server is in draining mode."""
        return self._draining_event.is_set()

    def register_worker(self, thread: threading.Thread) -> None:
        """Register a worker thread for tracking."""
        with self._lock:
            self._workers.add(thread)
            if LIFECYCLE_LOGGER.isEnabledFor(logging.DEBUG):
                LIFECYCLE_LOGGER.debug(
                    "Worker thread registered",
                    extra={
                        "event": "worker_registered",
                        "worker_count": len(self._workers),
                    },
                )

    def cleanup_worker(self, thread: threading.Thread) -> None:
        """Remove a worker thread from tracking."""
        with self._lock:
            self._workers.discard(thread)
            if LIFECYCLE_LOGGER.isEnabledFor(logging.DEBUG):
                LIFECYCLE_LOGGER.debug(
                    "Worker thread unregistered",
                    extra={
                        "event": "worker_unregistered",
                        "worker_count": len(self._workers),
                    },
                )

    def has_worker(self, thread: threading.Thread) -> bool:
        """Return True when the worker is currently tracked."""
        with self._lock:
            return thread in self._workers

    def active_worker_count(self) -> int:
        """Return the number of currently tracked worker threads."""
        with self._lock:
            return len(self._workers)

    def begin_draining(self) -> None:
        """Signal the server to begin graceful shutdown."""
        self._draining_event.set()
        self._stop_event.set()
        LIFECYCLE_LOGGER.info(
            "Graceful shutdown initiated", extra={"event": "draining_started"}
        )

    def _active_workers(self) -> list[threading.Thread]:
        with self._lock:
            self._workers = {w for w in self._workers if w.is_alive()}
            return list(self._workers)

    def _log_grace_expired(
        self, active_workers: list[threading.Thread], timeout: float
    ) -> None:
        LIFECYCLE_LOGGER.warning(
            "Shutdown grace period expired",
            extra={
                "event": "shutdown_grace_expired",
                "remaining_workers": len(active_workers),
                "timeout": timeout,
            },
        )

    @staticmethod
    def _join_workers_until(
        active_workers: list[threading.Thread], deadline: float, remaining: float
    ) -> None:
        for worker in active_workers:
            worker.join(timeout=min(0.1, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

    def wait_for_workers(self, timeout: float) -> bool:
        """Wait for all worker threads to complete within the timeout."""
        deadline = time.monotonic() + timeout
        while True:
            active_workers = self._active_workers()
            if not active_workers:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._log_grace_expired(active_workers, timeout)
                return False
            self._join_workers_until(active_workers, deadline, remaining)
