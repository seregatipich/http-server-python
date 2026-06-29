"""Unit tests for the upstream forwarder error handling (F8)."""

from unittest.mock import MagicMock, patch

import pytest

from pyhttpd.adapters.proxy import upstream
from pyhttpd.domain import BadRequest
from pyhttpd.domain.proxy import parse_proxy_pass

_TARGET = parse_proxy_pass("/api/=http://backend:80")


def test_forward_maps_unencodable_request_to_bad_request():
    """Client bytes that cannot be encoded for the upstream must yield 400, not 500."""
    connection = MagicMock()
    connection.request.side_effect = UnicodeEncodeError(
        "latin-1", "€", 0, 1, "ordinal not in range"
    )
    with patch.object(upstream, "_open_connection", return_value=connection):
        with pytest.raises(BadRequest):
            upstream.forward(_TARGET, "GET", "/€", {}, b"", 5.0)
    connection.close.assert_called_once()
