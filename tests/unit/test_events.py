from erebus.core.events import Event, EventBus


def test_pubsub_and_unsubscribe():
    bus = EventBus()
    got = []
    unsub = bus.subscribe("x", lambda e: got.append(e.data.get("a")))
    bus.publish(Event("x", {"a": 1}))
    assert got == [1]
    unsub()
    bus.publish(Event("x", {"a": 2}))
    assert got == [1]


def test_wildcard_subscriber():
    bus = EventBus()
    seen = []
    bus.subscribe(None, lambda e: seen.append(e.type))
    bus.publish(Event("a"))
    bus.publish(Event("b"))
    assert seen == ["a", "b"]


def test_bad_subscriber_does_not_break_bus():
    bus = EventBus()
    ok = []

    def boom(_e):
        raise RuntimeError("nope")

    bus.subscribe("x", boom)
    bus.subscribe("x", lambda e: ok.append(1))
    bus.publish(Event("x"))
    assert ok == [1]
