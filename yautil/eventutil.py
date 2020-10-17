from typing import Union


class Event:
    def on_event(self) -> None:
        raise NotImplementedError

    @classmethod
    def gen_event(cls, base_event):
        raise NotImplementedError


class EventGenerator:
    events: dict

    def __init__(self):
        self.events = {}

    def register_event(self, base_event_cls, derived_event_cls):
        if base_event_cls in self.events:
            self.events[base_event_cls].append(derived_event_cls)
        else:
            self.events[base_event_cls] = [derived_event_cls]

    def throw_event(self, event):
        event.on_event()
        try:
            for derived_event_class in self.events[event.__class__]:
                derived_event = derived_event_class.gen_event(event)
                if derived_event is not None:
                    self.throw_event(derived_event)
        except KeyError:
            pass
