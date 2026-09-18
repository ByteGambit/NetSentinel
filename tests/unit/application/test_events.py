"""Tests for deterministic, failure-isolating application event dispatch."""

from __future__ import annotations

from dataclasses import dataclass

from netsentinel.application.events import EventDispatcher


@dataclass(frozen=True)
class ExampleEvent:
    value: int


def test_subscribers_receive_an_event_in_subscription_order() -> None:
    dispatcher = EventDispatcher()
    received: list[tuple[str, int]] = []
    dispatcher.subscribe(ExampleEvent, lambda event: received.append(("first", event.value)))
    dispatcher.subscribe(ExampleEvent, lambda event: received.append(("second", event.value)))

    report = dispatcher.publish(ExampleEvent(7))

    assert received == [("first", 7), ("second", 7)]
    assert report.delivered == 2
    assert report.failed == 0


def test_subscriber_exception_isolated_from_later_subscribers() -> None:
    dispatcher = EventDispatcher()
    received: list[int] = []

    def failing(event: ExampleEvent) -> None:
        raise RuntimeError("subscriber-private detail")

    dispatcher.subscribe(ExampleEvent, failing)
    dispatcher.subscribe(ExampleEvent, lambda event: received.append(event.value))

    report = dispatcher.publish(ExampleEvent(9))

    assert received == [9]
    assert report.delivered == 1
    assert report.failed == 1


def test_unsubscribe_is_deterministic_and_idempotent() -> None:
    dispatcher = EventDispatcher()
    received: list[int] = []
    subscription = dispatcher.subscribe(
        ExampleEvent, lambda event: received.append(event.value)
    )

    dispatcher.publish(ExampleEvent(1))
    assert dispatcher.unsubscribe(subscription) is True
    assert dispatcher.unsubscribe(subscription) is False
    dispatcher.publish(ExampleEvent(2))

    assert received == [1]


def test_subscription_mutation_during_publish_applies_to_next_event() -> None:
    dispatcher = EventDispatcher()
    received: list[str] = []
    second = dispatcher.subscribe(
        ExampleEvent, lambda event: received.append("second")
    )

    def first(event: ExampleEvent) -> None:
        received.append("first")
        dispatcher.unsubscribe(second)

    # Rebuild order so the mutating subscriber runs first.
    dispatcher.unsubscribe(second)
    dispatcher.subscribe(ExampleEvent, first)
    second = dispatcher.subscribe(
        ExampleEvent, lambda event: received.append("second")
    )

    dispatcher.publish(ExampleEvent(1))
    dispatcher.publish(ExampleEvent(2))

    assert received == ["first", "second", "first"]


def test_only_exact_event_type_subscribers_receive_event() -> None:
    dispatcher = EventDispatcher()
    received: list[object] = []
    dispatcher.subscribe(object, received.append)
    dispatcher.subscribe(ExampleEvent, received.append)

    dispatcher.publish(ExampleEvent(3))

    assert received == [ExampleEvent(3)]
