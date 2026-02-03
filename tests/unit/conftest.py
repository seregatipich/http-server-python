"""Shared fixtures for unit tests."""

import logging

import pytest


@pytest.fixture(autouse=True)
def enable_log_propagation():
    """Ensure logs propagate to root so caplog can catch them."""
    logger = logging.getLogger("http_server")
    old_propagate = logger.propagate
    logger.propagate = True
    yield
    logger.propagate = old_propagate
