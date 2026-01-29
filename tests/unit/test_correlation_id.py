"""Unit tests for correlation ID functionality."""

import logging
import threading
import uuid
from unittest.mock import MagicMock

from correlation_id import (
    CorrelationLoggerAdapter,
    clear_correlation_id,
    generate_correlation_id,
    get_correlation_id,
    set_correlation_id,
)


class TestCorrelationIdContext:
    """Test correlation ID context management."""

    def test_generate_correlation_id_returns_uuid(self):
        """Generate IDs are UUID strings."""
        correlation_id = generate_correlation_id()
        assert correlation_id is not None
        assert isinstance(correlation_id, str)
        uuid.UUID(correlation_id)

    def test_generate_correlation_id_returns_unique_values(self):
        """Successive IDs should differ."""
        id1 = generate_correlation_id()
        id2 = generate_correlation_id()
        assert id1 != id2

    def test_get_correlation_id_returns_none_initially(self):
        """Unset context returns None."""
        clear_correlation_id()
        assert get_correlation_id() is None

    def test_set_and_get_correlation_id(self):
        """Setters reflect via getter."""
        test_id = "test-correlation-id-123"
        set_correlation_id(test_id)
        assert get_correlation_id() == test_id

    def test_clear_correlation_id(self):
        """Clearing removes stored ID."""
        set_correlation_id("test-id")
        assert get_correlation_id() is not None
        clear_correlation_id()
        assert get_correlation_id() is None

    def test_correlation_id_isolated_between_contexts(self):
        """Separate threads keep independent IDs."""

        results = {}

        def worker(worker_id: str):
            correlation_id = f"worker-{worker_id}"
            set_correlation_id(correlation_id)
            results[worker_id] = get_correlation_id()
            clear_correlation_id()

        threads = [threading.Thread(target=worker, args=(str(i),)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        for worker_id, correlation_id in results.items():
            assert correlation_id == f"worker-{worker_id}"


class TestCorrelationLoggerAdapter:
    """Test CorrelationLoggerAdapter behavior."""

    def test_adapter_injects_correlation_id_into_extra(self):
        """Adapter copies ID into extra."""
        mock_logger = MagicMock(spec=logging.Logger)
        adapter = CorrelationLoggerAdapter(mock_logger, {})

        test_id = "test-correlation-123"
        set_correlation_id(test_id)

        adapter.info("Test message")

        mock_logger.log.assert_called_once()
        call_args = mock_logger.log.call_args
        assert "extra" in call_args.kwargs
        assert call_args.kwargs["extra"]["correlation_id"] == test_id

        clear_correlation_id()

    def test_adapter_handles_missing_correlation_id(self):
        """Adapter tolerates missing IDs."""
        mock_logger = MagicMock(spec=logging.Logger)
        adapter = CorrelationLoggerAdapter(mock_logger, {})

        clear_correlation_id()
        adapter.info("Test message")

        mock_logger.log.assert_called_once()
        call_args = mock_logger.log.call_args
        extra = call_args.kwargs.get("extra", {})
        assert "correlation_id" not in extra

    def test_adapter_preserves_existing_extra_fields(self):
        """Adapter keeps existing extra fields."""
        mock_logger = MagicMock(spec=logging.Logger)
        adapter = CorrelationLoggerAdapter(mock_logger, {})

        test_id = "test-correlation-456"
        set_correlation_id(test_id)

        adapter.info("Test message", extra={"custom_field": "custom_value"})

        mock_logger.log.assert_called_once()
        call_args = mock_logger.log.call_args
        assert "extra" in call_args.kwargs
        assert call_args.kwargs["extra"]["correlation_id"] == test_id
        assert call_args.kwargs["extra"]["custom_field"] == "custom_value"

        clear_correlation_id()

    def test_adapter_does_not_modify_original_extra_dict(self):
        """Original extra dict remains untouched."""
        mock_logger = MagicMock(spec=logging.Logger)
        adapter = CorrelationLoggerAdapter(mock_logger, {})

        test_id = "test-correlation-789"
        set_correlation_id(test_id)

        original_extra = {"field": "value"}
        adapter.info("Test message", extra=original_extra)

        assert "correlation_id" not in original_extra
        assert original_extra == {"field": "value"}

        clear_correlation_id()
