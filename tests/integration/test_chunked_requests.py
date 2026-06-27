"""Integration tests for opt-in chunked requests and 100-continue (F1)."""

from __future__ import annotations

import socket

import pytest

from tests.characterization.raw_client import send_raw

pytestmark = pytest.mark.integration


def _status_line(raw: bytes) -> bytes:
    return raw.split(b"\r\n", 1)[0]


def test_chunked_request_rejected_by_default(server_process) -> None:
    """Without the opt-in flag, a chunked request still yields the 400 golden."""

    request = (
        b"POST /files/x.txt HTTP/1.1\r\nHost: x\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        b"3\r\nabc\r\n0\r\n\r\n"
    )
    raw = send_raw(server_process["host"], server_process["port"], request)
    assert _status_line(raw) == b"HTTP/1.1 400 Bad Request"


def test_chunked_upload_round_trips(chunked_server_process) -> None:
    """A chunked POST is decoded; the stored bytes match the reassembled body."""

    host = chunked_server_process["host"]
    port = chunked_server_process["port"]
    upload = (
        b"POST /files/chunked.txt HTTP/1.1\r\nHost: x\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n"
    )
    raw = send_raw(host, port, upload)
    assert _status_line(raw).startswith(b"HTTP/1.1 201")

    get_request = (
        b"GET /files/chunked.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    raw_get = send_raw(host, port, get_request)
    assert b"foobar" in raw_get


def test_chunked_te_with_content_length_rejected(chunked_server_process) -> None:
    """Even with chunked enabled, Transfer-Encoding + Content-Length is rejected."""

    request = (
        b"POST /files/smuggle.txt HTTP/1.1\r\nHost: x\r\n"
        b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n"
        b"Connection: close\r\n\r\n"
        b"3\r\nabc\r\n0\r\n\r\n"
    )
    raw = send_raw(
        chunked_server_process["host"], chunked_server_process["port"], request
    )
    assert _status_line(raw) == b"HTTP/1.1 400 Bad Request"


def test_expect_100_continue_interim_response(chunked_server_process) -> None:
    """A request advertising Expect: 100-continue receives the interim status."""

    host = chunked_server_process["host"]
    port = chunked_server_process["port"]
    with socket.create_connection((host, port), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(
            b"POST /files/continue.txt HTTP/1.1\r\nHost: x\r\n"
            b"Content-Length: 5\r\nExpect: 100-continue\r\n"
            b"Connection: close\r\n\r\n"
        )
        interim = conn.recv(4096)
        assert interim.startswith(b"HTTP/1.1 100 Continue\r\n\r\n")

        conn.sendall(b"hello")
        final = b""
        while b"\r\n\r\n" not in final:
            received = conn.recv(4096)
            if not received:
                break
            final += received
        assert final.startswith(b"HTTP/1.1 2")
