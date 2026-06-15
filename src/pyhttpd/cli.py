"""HTTP server entry point."""

import sys

from pyhttpd.adapters.config.cli_args import parse_cli_args
from pyhttpd.composition import build_server


def main() -> None:
    """Start the HTTP server and spawn worker threads per connection."""
    args = parse_cli_args(sys.argv[1:])
    build_server(args).serve()
