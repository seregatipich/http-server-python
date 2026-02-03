"""Shim module for backward compatibility.

This module re-exports the logging configuration from the new location.
Consumers should migrate to server.bootstrap.logging_setup.
"""

from server.bootstrap.logging_setup import configure_logging

__all__ = ["configure_logging"]
