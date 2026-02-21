"""Tests for EventBus."""

from aisec.core.events import EventBus


def test_event_bus_on_and_emit():
    bus = EventBus()
    received = []
    bus.on("test", lambda data: received.append(data))
    bus.emit("test", "hello")
    assert received == ["hello"]


def test_event_bus_multiple_handlers():
    bus = EventBus()
    results = []
    bus.on("evt", lambda x: results.append(f"a:{x}"))
    bus.on("evt", lambda x: results.append(f"b:{x}"))
    bus.emit("evt", 42)
    assert results == ["a:42", "b:42"]


def test_event_bus_no_handlers():
    bus = EventBus()
    # Should not raise
    bus.emit("nonexistent", "data")


def test_event_bus_clear():
    bus = EventBus()
    received = []
    bus.on("test", lambda: received.append(1))
    bus.clear()
    bus.emit("test")
    assert received == []


def test_event_bus_handler_error_doesnt_break():
    bus = EventBus()
    results = []

    def bad_handler(x):
        raise RuntimeError("boom")

    def good_handler(x):
        results.append(x)

    bus.on("evt", bad_handler)
    bus.on("evt", good_handler)
    bus.emit("evt", "ok")
    assert results == ["ok"]
