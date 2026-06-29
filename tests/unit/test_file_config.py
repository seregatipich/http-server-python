"""Unit tests for TOML config-file overlay (F11a)."""

from argparse import Namespace

from pyhttpd.adapters.config.file_config import (
    apply_overlay,
    load_config_file,
    reapply_overlay,
    record_explicit_flags,
)


def test_load_config_file_normalizes_keys(tmp_path) -> None:
    config = tmp_path / "c.toml"
    config.write_text('error-format = "json"\nmax_connections = 50\n')
    assert load_config_file(str(config)) == {
        "error_format": "json",
        "max_connections": 50,
    }


def test_apply_overlay_file_overrides_env_default() -> None:
    namespace = Namespace(error_format="text", port=4221)
    apply_overlay(namespace, {"error_format": "json"}, argv=[])
    assert namespace.error_format == "json"


def test_apply_overlay_explicit_cli_wins_over_file() -> None:
    namespace = Namespace(error_format="text")
    apply_overlay(namespace, {"error_format": "json"}, argv=["--error-format", "text"])
    assert namespace.error_format == "text"


def test_apply_overlay_respects_negated_boolean_flag() -> None:
    namespace = Namespace(metrics=True)
    apply_overlay(namespace, {"metrics": True}, argv=["--no-metrics"])
    assert namespace.metrics is True


def test_apply_overlay_ignores_unknown_keys() -> None:
    namespace = Namespace(port=4221)
    apply_overlay(namespace, {"unknown": "x"}, argv=[])
    assert not hasattr(namespace, "unknown")


def test_reapply_overlay_sets_known_keys_only() -> None:
    namespace = Namespace(error_format="text")
    reapply_overlay(namespace, {"error_format": "json", "unknown": 1})
    assert namespace.error_format == "json"
    assert not hasattr(namespace, "unknown")


def test_reapply_overlay_preserves_explicit_cli_flags() -> None:
    namespace = Namespace(error_format="text")
    record_explicit_flags(namespace, ["--error-format", "text"])
    reapply_overlay(namespace, {"error_format": "json"})
    assert namespace.error_format == "text"


def test_reapply_overlay_updates_fields_not_set_on_cli() -> None:
    namespace = Namespace(error_format="text")
    record_explicit_flags(namespace, [])
    reapply_overlay(namespace, {"error_format": "json"})
    assert namespace.error_format == "json"
