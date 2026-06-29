"""Unit tests for the /healthz handler."""

from pyhttpd.application import make_healthz_handler
from tests.unit._helpers import RecordingLogger, make_context, make_request


def test_healthz_keeps_alive_by_default():
    handler = make_healthz_handler(None, RecordingLogger())
    response = handler(make_request(path="/healthz"), make_context())
    assert response.status_line == "HTTP/1.1 200 OK"
    assert response.close_connection is False


def test_healthz_honors_connection_close():
    handler = make_healthz_handler(None, RecordingLogger())
    response = handler(
        make_request(path="/healthz", headers={"connection": "close"}), make_context()
    )
    assert response.close_connection is True
