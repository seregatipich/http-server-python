"""Unit tests for environment variable parsing helpers."""

import pytest

from pyhttpd.adapters.config import _env_bool, _env_int, _env_list

VAR = "HTTP_SERVER_TEST_ENV"


def test_env_int_returns_default_when_unset(monkeypatch):
    """_env_int returns the default when the variable is absent."""
    monkeypatch.delenv(VAR, raising=False)
    assert _env_int(VAR, 42) == 42


def test_env_int_parses_positive_value(monkeypatch):
    """_env_int parses a plain positive integer string."""
    monkeypatch.setenv(VAR, "8080")
    assert _env_int(VAR, 0) == 8080


def test_env_int_parses_negative_value(monkeypatch):
    """_env_int parses a negative integer string."""
    monkeypatch.setenv(VAR, "-7")
    assert _env_int(VAR, 0) == -7


def test_env_int_parses_zero_overriding_default(monkeypatch):
    """_env_int parses zero rather than falling back to the default."""
    monkeypatch.setenv(VAR, "0")
    assert _env_int(VAR, 99) == 0


def test_env_int_strips_surrounding_whitespace(monkeypatch):
    """_env_int parses values padded with surrounding whitespace."""
    monkeypatch.setenv(VAR, "  15  ")
    assert _env_int(VAR, 0) == 15


def test_env_int_raises_on_non_numeric(monkeypatch):
    """_env_int raises ValueError on a non-numeric value."""
    monkeypatch.setenv(VAR, "not-a-number")
    with pytest.raises(ValueError):
        _env_int(VAR, 0)


def test_env_int_raises_on_empty_string(monkeypatch):
    """_env_int raises ValueError when the value is an empty string."""
    monkeypatch.setenv(VAR, "")
    with pytest.raises(ValueError):
        _env_int(VAR, 0)


def test_env_bool_returns_default_when_unset(monkeypatch):
    """_env_bool returns the default when the variable is absent."""
    monkeypatch.delenv(VAR, raising=False)
    assert _env_bool(VAR, True) is True
    assert _env_bool(VAR, False) is False


@pytest.mark.parametrize("truthy", ["1", "true", "yes", "on"])
def test_env_bool_recognizes_truthy_tokens(monkeypatch, truthy):
    """_env_bool treats the documented truthy tokens as True."""
    monkeypatch.setenv(VAR, truthy)
    assert _env_bool(VAR, False) is True


@pytest.mark.parametrize("truthy", ["TRUE", "Yes", "On", "tRuE"])
def test_env_bool_is_case_insensitive(monkeypatch, truthy):
    """_env_bool lowercases the value before matching truthy tokens."""
    monkeypatch.setenv(VAR, truthy)
    assert _env_bool(VAR, False) is True


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "", "maybe"])
def test_env_bool_treats_other_values_as_false(monkeypatch, falsy):
    """_env_bool returns False for any value outside the truthy set."""
    monkeypatch.setenv(VAR, falsy)
    assert _env_bool(VAR, True) is False


def test_env_bool_does_not_strip_whitespace(monkeypatch):
    """_env_bool does not trim whitespace, so padded tokens are False."""
    monkeypatch.setenv(VAR, " true ")
    assert _env_bool(VAR, False) is False


def test_env_list_returns_default_when_unset(monkeypatch):
    """_env_list returns the default list when the variable is absent."""
    monkeypatch.delenv(VAR, raising=False)
    default = ["*"]
    assert _env_list(VAR, default) is default


def test_env_list_splits_on_commas(monkeypatch):
    """_env_list splits the value on commas into separate items."""
    monkeypatch.setenv(VAR, "a,b,c")
    assert _env_list(VAR, []) == ["a", "b", "c"]


def test_env_list_strips_item_whitespace(monkeypatch):
    """_env_list trims surrounding whitespace from each item."""
    monkeypatch.setenv(VAR, " a , b ,c ")
    assert _env_list(VAR, []) == ["a", "b", "c"]


def test_env_list_drops_empty_items(monkeypatch):
    """_env_list discards empty and whitespace-only segments."""
    monkeypatch.setenv(VAR, "a,,  ,b,")
    assert _env_list(VAR, []) == ["a", "b"]


def test_env_list_empty_string_yields_empty_list(monkeypatch):
    """_env_list maps an empty string to an empty list, not the default."""
    monkeypatch.setenv(VAR, "")
    assert _env_list(VAR, ["fallback"]) == []


def test_env_list_single_value_without_comma(monkeypatch):
    """_env_list returns a single-element list for a comma-free value."""
    monkeypatch.setenv(VAR, "solo")
    assert _env_list(VAR, []) == ["solo"]
