"""Unit tests for the connection-takeover seam (SEAM)."""

from unittest.mock import MagicMock, patch

from pyhttpd.adapters.transport.channel import SocketChannel
from pyhttpd.adapters.transport.context import WorkerContext
from pyhttpd.adapters.transport.worker import _perform_upgrade, _process_request
from pyhttpd.domain import HttpRequest, HttpResponse


def test_socket_channel_delegates_to_socket() -> None:
    sock = MagicMock()
    sock.recv.return_value = b"data"
    channel = SocketChannel(sock)

    assert channel.read(10) == b"data"
    channel.write(b"out")
    sock.sendall.assert_called_once_with(b"out")
    channel.close()
    sock.close.assert_called_once()


def test_perform_upgrade_writes_handshake_and_invokes_driver() -> None:
    sock = MagicMock()
    captured: dict[str, object] = {}

    def driver(channel: SocketChannel) -> None:
        captured["channel"] = channel

    response = HttpResponse(
        "HTTP/1.1 101 Switching Protocols",
        {"Upgrade": "websocket", "Connection": "Upgrade"},
        b"",
        True,
        upgrade=driver,
    )

    result = _perform_upgrade(sock, response)

    assert result is True
    sent = sock.sendall.call_args[0][0]
    assert sent.startswith(b"HTTP/1.1 101 Switching Protocols\r\n")
    assert b"Upgrade: websocket\r\n" in sent
    assert sent.endswith(b"\r\n\r\n")
    assert b"Content-Length" not in sent
    sock.settimeout.assert_called_once_with(None)
    assert isinstance(captured["channel"], SocketChannel)


def _run_process_request(response: HttpResponse):
    sock = MagicMock()
    context = MagicMock(spec=WorkerContext)
    context.error_format = "text"
    context.cors_config = None
    request = HttpRequest("GET", "/events", {}, b"")
    with (
        patch(
            "pyhttpd.adapters.transport.worker._build_request_chain",
            return_value=lambda _req, _ctx: response,
        ),
        patch("pyhttpd.adapters.transport.worker.send_response") as send,
        patch(
            "pyhttpd.adapters.transport.worker._apply_handler_timeout"
        ) as apply_timeout,
    ):
        result = _process_request(request, context, sock, "1.2.3.4", "1.2.3.4:1", 1024)
    return result, send, apply_timeout


def test_streaming_response_skips_handler_timeout() -> None:
    response = HttpResponse(
        "HTTP/1.1 200 OK",
        {},
        b"",
        False,
        body_iter=iter([b"x"]),
        use_chunked=True,
        streaming=True,
    )
    result, send, apply_timeout = _run_process_request(response)

    apply_timeout.assert_not_called()
    send.assert_called_once()
    assert result is False


def test_non_streaming_response_applies_handler_timeout() -> None:
    response = HttpResponse("HTTP/1.1 200 OK", {}, b"ok", False)
    _result, send, apply_timeout = _run_process_request(response)

    apply_timeout.assert_called_once()
    send.assert_called_once()
