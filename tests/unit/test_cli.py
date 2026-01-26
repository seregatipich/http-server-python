"""Golden unit tests validating CLI parsing behavior."""

from main import parse_cli_args


def test_parse_cli_args_uses_defaults():
    """Defaults ensure server launches with local settings."""
    args = parse_cli_args([])

    assert args.directory == "."
    assert args.host == "localhost"
    assert args.port == 4221
    assert args.log_level == "INFO"
    assert args.log_destination == "stdout"


def test_parse_cli_args_honors_overrides(tmp_path):
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
        ]
    )

    assert args.directory == override_dir
    assert args.host == "0.0.0.0"
    assert args.port == 9090
    assert args.log_level == "DEBUG"
    assert args.log_destination == "server.log"


def test_parse_cli_args_honors_environment(monkeypatch):
    """Environment variables should seed default logging configuration."""

    monkeypatch.setenv("HTTP_SERVER_LOG_LEVEL", "warning")
    monkeypatch.setenv("HTTP_SERVER_LOG_DESTINATION", "app.log")

    args = parse_cli_args([])

    assert args.log_level == "WARNING"
    assert args.log_destination == "app.log"
