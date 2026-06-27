"""Integration tests for the WebSocket echo endpoint (F7)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
import requests

from pyhttpd.domain.websocket import (
    OPCODE_CLOSE,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
    compute_accept,
)
from tests.utils.websocket import open_connection, recv, send

pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from tests.conftest import ServerProcessInfo


def test_handshake_echo_ping_and_close(
    websocket_server_process: "ServerProcessInfo",
) -> None:
    host = websocket_server_process["host"]
    port = websocket_server_process["port"]
    sock, response, key = open_connection(host, port)
    try:
        assert b"101 Switching Protocols" in response
        assert compute_accept(key).encode() in response

        send(sock, OPCODE_TEXT, b"hello websocket")
        opcode, payload = recv(sock)
        assert opcode == OPCODE_TEXT
        assert payload == b"hello websocket"

        send(sock, OPCODE_PING, b"ping-payload")
        opcode, payload = recv(sock)
        assert opcode == OPCODE_PONG
        assert payload == b"ping-payload"

        send(sock, OPCODE_CLOSE, struct.pack("!H", 1000))
        opcode, _payload = recv(sock)
        assert opcode == OPCODE_CLOSE
    finally:
        sock.close()


def test_non_upgrade_request_is_bad_request(
    websocket_server_process: "ServerProcessInfo",
) -> None:
    response = requests.get(f"{websocket_server_process['base_url']}/ws", timeout=5)
    assert response.status_code == 400


def test_websocket_disabled_by_default(server_process: "ServerProcessInfo") -> None:
    response = requests.get(f"{server_process['base_url']}/ws", timeout=5)
    assert response.status_code == 404
