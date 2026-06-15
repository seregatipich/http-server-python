"""Unit tests for the CLI entry point and the ``python -m pyhttpd`` shim."""

import pyhttpd.__main__ as entry
from pyhttpd import cli


def test_main_wires_parse_build_and_serve(monkeypatch):
    """main parses argv, builds the server, and serves exactly once."""
    calls = {}

    def _fake_parse(argv):
        calls["argv"] = argv
        return "ARGS"

    class _FakeServer:  # pylint: disable=too-few-public-methods
        """Records that serve was invoked."""

        def serve(self):
            """Mark the server as served."""
            calls["served"] = True

    def _fake_build(args):
        calls["build_args"] = args
        return _FakeServer()

    monkeypatch.setattr(cli, "parse_cli_args", _fake_parse)
    monkeypatch.setattr(cli, "build_server", _fake_build)
    monkeypatch.setattr(cli.sys, "argv", ["pyhttpd", "--port", "4221"])

    cli.main()

    assert calls["argv"] == ["--port", "4221"]
    assert calls["build_args"] == "ARGS"
    assert calls["served"] is True


def test_dunder_main_reexports_cli_main():
    """The ``python -m pyhttpd`` entry re-exports cli.main."""
    assert entry.main is cli.main
