"""Unit tests for the in-memory session store (F4)."""

from pyhttpd.adapters.session.store import InMemorySessionStore


class FakeClock:
    """Deterministic monotonic clock for TTL tests."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_create_and_get_returns_mutable_dict_that_persists() -> None:
    store = InMemorySessionStore(ttl_seconds=100)
    session_id = store.create()
    data = store.get(session_id)
    assert data == {}
    data["user"] = "alice"
    refetched = store.get(session_id)
    assert refetched is not None
    assert refetched["user"] == "alice"


def test_get_unknown_returns_none() -> None:
    store = InMemorySessionStore(ttl_seconds=100)
    assert store.get("missing") is None


def test_ttl_eviction_after_expiry() -> None:
    clock = FakeClock()
    store = InMemorySessionStore(ttl_seconds=10, now=clock)
    session_id = store.create()
    clock.now = 9
    assert store.get(session_id) is not None  # within TTL, slides expiry to 19
    clock.now = 100
    assert store.get(session_id) is None


def test_capacity_eviction_drops_oldest() -> None:
    clock = FakeClock()
    store = InMemorySessionStore(ttl_seconds=1000, max_entries=2, now=clock)
    first = store.create()
    clock.now = 1
    second = store.create()
    clock.now = 2
    third = store.create()
    assert store.get(first) is None
    assert store.get(second) is not None
    assert store.get(third) is not None
