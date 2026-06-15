"""Unit tests for runtime adapters and their conformance to domain ports."""

import re
import uuid
from typing import Protocol, runtime_checkable

from pyhttpd.adapters.clock import MonotonicClock
from pyhttpd.adapters.ids import Uuid4IdGenerator
from pyhttpd.adapters.transport import wire
from pyhttpd.domain.ports import Clock, IdGenerator


def test_monotonic_clock_now_ns_returns_int():
    """MonotonicClock.now_ns returns a plain int reading."""
    reading = MonotonicClock().now_ns()
    assert isinstance(reading, int)
    assert not isinstance(reading, bool)


def test_monotonic_clock_is_non_decreasing_across_calls():
    """MonotonicClock readings never move backwards between two calls."""
    clock = MonotonicClock()
    first = clock.now_ns()
    second = clock.now_ns()
    assert second >= first


def test_uuid4_id_generator_returns_valid_uuid4_string():
    """Uuid4IdGenerator.new_id returns a canonical version-4 UUID string."""
    new_id = Uuid4IdGenerator().new_id()
    assert isinstance(new_id, str)
    parsed = uuid.UUID(new_id)
    assert parsed.version == 4
    assert str(parsed) == new_id


def test_uuid4_id_generator_produces_distinct_ids():
    """Successive Uuid4IdGenerator calls yield distinct identifiers."""
    generator = Uuid4IdGenerator()
    ids = {generator.new_id() for _ in range(64)}
    assert len(ids) == 64


def test_format_client_address_renders_ip_port():
    """format_client_address joins host and port with a colon."""
    assert wire.format_client_address(("127.0.0.1", 8080)) == "127.0.0.1:8080"


def test_format_client_address_supports_ipv6_host():
    """format_client_address renders any host string followed by its port."""
    assert wire.format_client_address(("::1", 443)) == "::1:443"


def test_header_delimiter_is_double_crlf():
    """HEADER_DELIMITER is the canonical end-of-headers byte sequence."""
    assert wire.HEADER_DELIMITER == b"\r\n\r\n"
    assert isinstance(wire.HEADER_DELIMITER, bytes)


@runtime_checkable
class _CheckableClock(Clock, Protocol):  # pylint: disable=too-few-public-methods
    """Runtime-checkable mirror of the Clock port for isinstance assertions."""


@runtime_checkable
class _CheckableIdGenerator(  # pylint: disable=too-few-public-methods
    IdGenerator, Protocol
):
    """Runtime-checkable mirror of the IdGenerator port."""


def test_monotonic_clock_conforms_to_clock_port():
    """MonotonicClock structurally satisfies the Clock protocol."""
    clock = MonotonicClock()
    assert isinstance(clock, _CheckableClock)
    assert hasattr(clock, "now_ns")
    assert isinstance(clock.now_ns(), int)


def test_uuid4_id_generator_conforms_to_id_generator_port():
    """Uuid4IdGenerator structurally satisfies the IdGenerator protocol."""
    generator = Uuid4IdGenerator()
    assert isinstance(generator, _CheckableIdGenerator)
    assert hasattr(generator, "new_id")
    assert isinstance(generator.new_id(), str)


def test_clock_port_method_signature_matches_adapter():
    """The Clock port declares now_ns, satisfied by the concrete adapter."""
    assert hasattr(Clock, "now_ns")
    assert callable(MonotonicClock.now_ns)


def test_id_generator_port_method_signature_matches_adapter():
    """The IdGenerator port declares new_id, satisfied by the concrete adapter."""
    assert hasattr(IdGenerator, "new_id")
    assert callable(Uuid4IdGenerator.new_id)


def test_clock_and_id_ports_do_not_cross_conform():
    """A clock is not an id generator and vice versa under the ports."""
    assert not isinstance(MonotonicClock(), _CheckableIdGenerator)
    assert not isinstance(Uuid4IdGenerator(), _CheckableClock)


def test_format_client_address_matches_legacy_regex():
    """format_client_address output matches the legacy host:port shape."""
    rendered = wire.format_client_address(("10.0.0.5", 51234))
    assert re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", rendered)
