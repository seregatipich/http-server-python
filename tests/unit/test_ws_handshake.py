"""Unit tests for the WebSocket opening-handshake handler (RFC 6455 4)."""

import pytest

from pyhttpd.application.handlers.websocket import make_websocket_handler
from pyhttpd.domain import BadRequest, UpgradeRequired
from tests.unit._helpers import RecordingLogger, make_context, make_request

_VALID_KEY = "dGhlIHNhbXBsZSBub25jZQ=="


def _headers(version="13", key=_VALID_KEY):
    headers = {"upgrade": "websocket", "connection": "Upgrade"}
    if version is not None:
        headers["sec-websocket-version"] = version
    if key is not None:
        headers["sec-websocket-key"] = key
    return headers


def test_valid_upgrade_returns_101():
    handler = make_websocket_handler(None, RecordingLogger())
    response = handler(make_request(path="/ws", headers=_headers()), make_context())
    assert response.status_line == "HTTP/1.1 101 Switching Protocols"
    assert response.upgrade is not None


def test_wrong_version_raises_upgrade_required():
    handler = make_websocket_handler(None, RecordingLogger())
    with pytest.raises(UpgradeRequired):
        handler(make_request(path="/ws", headers=_headers(version="8")), make_context())


def test_non_upgrade_raises_bad_request():
    handler = make_websocket_handler(None, RecordingLogger())
    with pytest.raises(BadRequest):
        handler(make_request(path="/ws", headers={}), make_context())
