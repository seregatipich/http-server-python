"""Backward-compatibility shim; transport now lives in adapters."""

import argparse

from pyhttpd.adapters.config.cli_args import ServerConfig
from pyhttpd.adapters.transport.connection_limiter import ConnectionLimiter
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.worker import _recv_with_deadline, handle_client
from pyhttpd.composition import build_server
from pyhttpd.domain import LifecycleState

__all__ = [
    "ConnectionLimiter",
    "WorkerContext",
    "_recv_with_deadline",
    "handle_client",
    "run_server",
]


def run_server(
    args: argparse.Namespace, config: ServerConfig, lifecycle: LifecycleState
) -> None:
    """Build the server and run its accept loop (legacy entry point)."""
    build_server(args, config, lifecycle).serve()
