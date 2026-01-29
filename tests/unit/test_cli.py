"""Golden unit tests validating CLI parsing behavior."""

from pathlib import Path
from typing import TYPE_CHECKING

from main import (
    DEFAULT_BURST_CAPACITY,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_IP,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RATE_LIMIT_DRY_RUN,
    DEFAULT_RATE_WINDOW_MS,
    parse_cli_args,
)

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_parse_cli_args_uses_defaults() -> None:
    """Defaults ensure server launches with local settings."""
    args = parse_cli_args([])

    assert args.directory == "."
    assert args.host == "localhost"
    assert args.port == 4221
    assert args.log_level == "INFO"
    assert args.log_destination == "stdout"
    assert args.max_connections == DEFAULT_MAX_CONNECTIONS
    assert args.max_connections_per_ip == DEFAULT_MAX_CONNECTIONS_PER_IP
    assert args.rate_limit == DEFAULT_RATE_LIMIT
    assert args.rate_window_ms == DEFAULT_RATE_WINDOW_MS
    assert args.burst_capacity == DEFAULT_BURST_CAPACITY
    assert args.rate_limit_dry_run is DEFAULT_RATE_LIMIT_DRY_RUN


def test_parse_cli_args_honors_overrides(tmp_path: Path) -> None:
    """Overrides should replace defaults when flags are present."""
    override_dir = tmp_path.as_posix()

    args = parse_cli_args(
        [
            "--directory",
            override_dir,
            "--host",
            "0.0.0.0",
            "--port",
            "9090",
            "--log-level",
            "debug",
            "--log-destination",
            "server.log",
            "--max-connections",
            "10",
            "--max-connections-per-ip",
            "3",
            "--rate-limit",
            "5",
            "--rate-window-ms",
            "2500",
            "--burst-capacity",
            "7",
            "--rate-limit-dry-run",
        ]
    )

    assert args.directory == override_dir
    assert args.host == "0.0.0.0"
    assert args.port == 9090
    assert args.log_level == "DEBUG"
    assert args.log_destination == "server.log"
    assert args.max_connections == 10
    assert args.max_connections_per_ip == 3
    assert args.rate_limit == 5
    assert args.rate_window_ms == 2500
    assert args.burst_capacity == 7
    assert args.rate_limit_dry_run is True


def test_parse_cli_args_honors_environment(monkeypatch: "MonkeyPatch") -> None:
    """Environment variables should seed default logging configuration."""

    monkeypatch.setenv("HTTP_SERVER_LOG_LEVEL", "warning")
    monkeypatch.setenv("HTTP_SERVER_LOG_DESTINATION", "app.log")

    args = parse_cli_args([])

    assert args.log_level == "WARNING"
    assert args.log_destination == "app.log"
