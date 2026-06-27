"""Integration tests for virtual-host routing (F9)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import requests

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_each_host_serves_its_own_directory(
    vhost_server: "ServerProcessInfo",
) -> None:
    base_url = vhost_server["base_url"]
    response_a = requests.get(
        f"{base_url}/files/hello.txt", headers={"Host": "a.test"}, timeout=5
    )
    response_b = requests.get(
        f"{base_url}/files/hello.txt", headers={"Host": "b.test"}, timeout=5
    )
    assert response_a.text == "from-a"
    assert response_b.text == "from-b"


def test_host_is_matched_case_insensitively(
    vhost_server: "ServerProcessInfo",
) -> None:
    response = requests.get(
        f"{vhost_server['base_url']}/files/hello.txt",
        headers={"Host": "A.TEST"},
        timeout=5,
    )
    assert response.text == "from-a"


def test_unknown_host_falls_back_to_default_root(
    vhost_server: "ServerProcessInfo",
) -> None:
    response = requests.get(
        f"{vhost_server['base_url']}/files/hello.txt",
        headers={"Host": "other.test"},
        timeout=5,
    )
    assert response.status_code == 404
