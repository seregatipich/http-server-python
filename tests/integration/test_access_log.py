"""Integration test for the Combined Log Format access log (F11b)."""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo

CLF_PATTERN = re.compile(
    r'^\S+ - - \[.+\] "GET /echo/logme HTTP/1\.1" 200 \d+ ".*" ".*"$',
    re.MULTILINE,
)


def _read_until(path, needle: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            content = path.read_text()
            if needle in content:
                return content
        time.sleep(0.05)
    return path.read_text() if path.exists() else ""


def test_access_log_records_combined_format(
    access_log_server: "ServerProcessInfo",
) -> None:
    response = requests.get(f"{access_log_server['base_url']}/echo/logme", timeout=5)
    assert response.status_code == 200

    access_path = access_log_server["directory"] / "access.log"
    content = _read_until(access_path, "/echo/logme")
    assert CLF_PATTERN.search(content)
