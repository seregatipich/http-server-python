"""Golden unit tests validating CLI parsing behavior."""

from main import parse_cli_args


def test_parse_cli_args_uses_defaults():
    args = parse_cli_args([])

    assert args.directory == "."
    assert args.host == "localhost"
    assert args.port == 4221


def test_parse_cli_args_honors_overrides(tmp_path):
    override_dir = tmp_path.as_posix()

    args = parse_cli_args(
        [
            "--directory",
            override_dir,
            "--host",
            "0.0.0.0",
            "--port",
            "9090",
        ]
    )

    assert args.directory == override_dir
    assert args.host == "0.0.0.0"
    assert args.port == 9090
