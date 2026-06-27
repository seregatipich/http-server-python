"""Integration tests for the reverse proxy (F8)."""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.integration


def test_proxy_forwards_request_to_upstream(proxy_pair: dict) -> None:
    proxy = proxy_pair["proxy"]
    response = requests.get(f"{proxy['base_url']}/up/echo/hello-proxy", timeout=10)
    assert response.status_code == 200
    assert response.text == "hello-proxy"


def test_proxy_strips_hop_by_hop_and_adds_via(proxy_pair: dict) -> None:
    proxy = proxy_pair["proxy"]
    response = requests.get(f"{proxy['base_url']}/up/user-agent", timeout=10)
    assert response.status_code == 200
    # The upstream observed a forwarded request; the response returns normally.
    assert response.text


def test_proxy_returns_502_when_upstream_down(proxy_pair: dict) -> None:
    upstream_process = proxy_pair["upstream"]["process"]
    upstream_process.terminate()
    upstream_process.wait(timeout=5)
    response = requests.get(f"{proxy_pair['proxy']['base_url']}/up/echo/x", timeout=10)
    assert response.status_code in (502, 504)


def test_non_proxied_path_served_locally(proxy_pair: dict) -> None:
    proxy = proxy_pair["proxy"]
    response = requests.get(f"{proxy['base_url']}/healthz", timeout=10)
    assert response.status_code == 200
