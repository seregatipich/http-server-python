"""Integration test for TOML config + SIGHUP reload (F11a)."""

from __future__ import annotations

import os
import signal
import time
from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def _content_type(base_url: str) -> str:
    response = requests.get(f"{base_url}/nope", timeout=5)
    return response.headers.get("Content-Type", "")


def test_sighup_reloads_error_format(
    config_reload_server: "ServerProcessInfo",
) -> None:
    base_url = config_reload_server["base_url"]
    assert "application/json" not in _content_type(base_url)

    config_path = config_reload_server["directory"] / "server.toml"
    config_path.write_text('error_format = "json"\n')
    os.kill(config_reload_server["process"].pid, signal.SIGHUP)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if "application/json" in _content_type(base_url):
            break
        time.sleep(0.1)
    assert "application/json" in _content_type(base_url)


def test_config_file_sets_initial_value(
    config_reload_server: "ServerProcessInfo",
) -> None:
    # The config file selected text error bodies; a 404 has no JSON content type.
    assert "application/json" not in _content_type(config_reload_server["base_url"])
