"""Unit tests for timeout and lifecycle functionality."""

import socket
import threading
import time
from unittest.mock import Mock

import pytest

from main import ServerConfig, ServerLifecycle, _recv_with_deadline


class TestRecvWithDeadline:
    """Tests for _recv_with_deadline helper function."""

    def test_recv_before_deadline(self):
        """Test successful recv before deadline expires."""
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"test data"
        deadline_ns = time.monotonic_ns() + 1_000_000_000
        result = _recv_with_deadline(mock_socket, deadline_ns)
        assert result == b"test data"
        mock_socket.settimeout.assert_called_once()
        timeout_arg = mock_socket.settimeout.call_args[0][0]
        assert 0 < timeout_arg <= 1.0

    def test_recv_after_deadline_expired(self):
        """Test TimeoutError raised when deadline already passed."""
        mock_socket = Mock(spec=socket.socket)
        deadline_ns = time.monotonic_ns() - 1_000_000_000
        with pytest.raises(TimeoutError, match="Request deadline exceeded"):
            _recv_with_deadline(mock_socket, deadline_ns)
        mock_socket.recv.assert_not_called()

    def test_recv_sets_socket_timeout_correctly(self):
        """Test that socket timeout is set based on remaining time."""
        mock_socket = Mock(spec=socket.socket)
        mock_socket.recv.return_value = b"data"
        deadline_ns = time.monotonic_ns() + 500_000_000
        _recv_with_deadline(mock_socket, deadline_ns)
        timeout_arg = mock_socket.settimeout.call_args[0][0]
        assert 0.4 < timeout_arg < 0.6


class TestServerLifecycle:
    """Tests for ServerLifecycle state management."""

    def test_initial_state(self):
        """Test lifecycle starts in non-draining, non-stopped state."""
        lifecycle = ServerLifecycle()
        assert not lifecycle.should_stop()
        assert not lifecycle.is_draining()

    def test_begin_draining_sets_flags(self):
        """Test begin_draining sets both draining and stop flags."""
        lifecycle = ServerLifecycle()
        lifecycle.begin_draining()
        assert lifecycle.should_stop()
        assert lifecycle.is_draining()

    def test_register_and_cleanup_worker(self):
        """Test worker thread registration and cleanup."""
        lifecycle = ServerLifecycle()

        def no_op():
            return None

        thread = threading.Thread(target=no_op)
        lifecycle.register_worker(thread)
        assert lifecycle.has_worker(thread)
        lifecycle.cleanup_worker(thread)
        assert not lifecycle.has_worker(thread)

    def test_cleanup_nonexistent_worker_is_safe(self):
        """Test cleanup of unregistered worker does not raise."""
        lifecycle = ServerLifecycle()

        def noop_worker():
            return None

        thread = threading.Thread(target=noop_worker)
        lifecycle.cleanup_worker(thread)

    def test_wait_for_workers_returns_true_when_empty(self):
        """Test wait_for_workers returns True when no workers active."""
        lifecycle = ServerLifecycle()
        result = lifecycle.wait_for_workers(timeout=1.0)
        assert result is True

    def test_wait_for_workers_waits_for_completion(self):
        """Test wait_for_workers waits for active threads to finish."""
        lifecycle = ServerLifecycle()
        completed = threading.Event()

        def worker():
            time.sleep(0.2)
            completed.set()

        thread = threading.Thread(target=worker)
        lifecycle.register_worker(thread)
        thread.start()
        result = lifecycle.wait_for_workers(timeout=2.0)
        assert result is True
        assert completed.is_set()

    def test_wait_for_workers_timeout_exceeded(self):
        """Test wait_for_workers returns False when timeout exceeded."""
        lifecycle = ServerLifecycle()

        def long_worker():
            time.sleep(10.0)

        thread = threading.Thread(target=long_worker)
        lifecycle.register_worker(thread)
        thread.start()
        start = time.monotonic()
        result = lifecycle.wait_for_workers(timeout=0.3)
        elapsed = time.monotonic() - start
        assert result is False
        assert 0.2 < elapsed < 0.5

    def test_multiple_workers_tracked(self):
        """Test multiple worker threads can be tracked simultaneously."""
        lifecycle = ServerLifecycle()

        def noop_task():
            return None

        threads = [threading.Thread(target=noop_task) for _ in range(5)]
        for thread in threads:
            lifecycle.register_worker(thread)
        assert lifecycle.active_worker_count() == 5
        for thread in threads:
            lifecycle.cleanup_worker(thread)
        assert lifecycle.active_worker_count() == 0


class TestServerConfig:
    """Tests for ServerConfig dataclass."""

    def test_config_creation(self):
        """Test ServerConfig can be created with expected fields."""
        config = ServerConfig(socket_timeout=30, shutdown_grace_seconds=15)
        assert config.socket_timeout == 30
        assert config.shutdown_grace_seconds == 15

    def test_config_with_custom_values(self):
        """Test ServerConfig accepts custom timeout values."""
        config = ServerConfig(socket_timeout=45, shutdown_grace_seconds=20)
        assert config.socket_timeout == 45
        assert config.shutdown_grace_seconds == 20
