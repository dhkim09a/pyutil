from __future__ import annotations

from typing import Type


class Event:
    def on_event(self) -> None:
        raise NotImplementedError

    @classmethod
    def gen_event(cls, base_event: Event) -> Event | None:
        raise NotImplementedError


class EventGenerator:
    events: dict[Type[Event], list[Type[Event]]]

    def __init__(self):
        self.events = {}

    def register_event(self, base_event_cls: Type[Event], derived_event_cls: Type[Event]):
        if base_event_cls in self.events:
            self.events[base_event_cls].append(derived_event_cls)
        else:
            self.events[base_event_cls] = [derived_event_cls]

    def throw_event(self, event: Event):
        event.on_event()

        if not (derived_event_classes := self.events.get(event.__class__)):
            return

        for derived_event_class in derived_event_classes:
            if (derived_event := derived_event_class.gen_event(event)) is None:
                continue
            self.throw_event(derived_event)
