from unittest import TestCase

from yautil.event import Event, EventGenerator


class TestEvent(TestCase):
    def test_on_event_default_not_implemented(self):
        e = Event()
        with self.assertRaises(NotImplementedError):
            e.on_event()

    def test_gen_event_default_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            Event.gen_event(Event())


class TestEventGenerator(TestCase):
    def test_throw_calls_on_event(self):
        calls = []

        class MyEvent(Event):
            def on_event(self):
                calls.append('on_event')

        gen = EventGenerator()
        gen.throw_event(MyEvent())
        self.assertEqual(calls, ['on_event'])

    def test_register_and_propagate(self):
        order = []

        class Base(Event):
            def on_event(self):
                order.append('base')

        class Derived(Event):
            def on_event(self):
                order.append('derived')

            @classmethod
            def gen_event(cls, base_event):
                return cls()

        gen = EventGenerator()
        gen.register_event(Base, Derived)
        gen.throw_event(Base())
        self.assertEqual(order, ['base', 'derived'])

    def test_gen_event_returning_none_skips_propagation(self):
        order = []

        class Base(Event):
            def on_event(self):
                order.append('base')

        class Derived(Event):
            def on_event(self):
                order.append('derived')

            @classmethod
            def gen_event(cls, base_event):
                return None

        gen = EventGenerator()
        gen.register_event(Base, Derived)
        gen.throw_event(Base())
        self.assertEqual(order, ['base'])

    def test_multiple_derived_classes(self):
        order = []

        class Base(Event):
            def on_event(self):
                order.append('base')

        class D1(Event):
            def on_event(self):
                order.append('d1')

            @classmethod
            def gen_event(cls, base_event):
                return cls()

        class D2(Event):
            def on_event(self):
                order.append('d2')

            @classmethod
            def gen_event(cls, base_event):
                return cls()

        gen = EventGenerator()
        gen.register_event(Base, D1)
        gen.register_event(Base, D2)
        gen.throw_event(Base())
        self.assertEqual(order, ['base', 'd1', 'd2'])

    def test_no_registered_derived_doesnt_crash(self):
        class Base(Event):
            def on_event(self):
                pass

        gen = EventGenerator()
        gen.throw_event(Base())  # should not raise
