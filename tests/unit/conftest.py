"""Shared fixtures for unit tests."""

import logging

import pytest

from pyhttpd.application import RequestContext


@pytest.fixture(autouse=True)
def enable_log_propagation():
    """Ensure logs propagate to root so caplog can catch them."""
    logger = logging.getLogger("http_server")
    old_propagate = logger.propagate
    logger.propagate = True
    yield
    logger.propagate = old_propagate


@pytest.fixture(name="ctx")
def fixture_ctx():
    """Build a request context for handler invocation."""
    return RequestContext(correlation_id="cid-1", start_ns=0)
