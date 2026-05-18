from unittest import TestCase

from yautil.decorators import static_vars


class TestStaticVars(TestCase):
    def test_single_attribute(self):
        @static_vars(count=0)
        def f():
            f.count += 1
            return f.count

        self.assertEqual(f.count, 0)
        self.assertEqual(f(), 1)
        self.assertEqual(f(), 2)

    def test_multiple_attributes(self):
        @static_vars(a=1, b='hello')
        def f():
            return (f.a, f.b)

        self.assertEqual(f(), (1, 'hello'))

    def test_decorator_returns_same_function(self):
        def f():
            return 1

        decorated = static_vars(x=5)(f)
        self.assertIs(decorated, f)
        self.assertEqual(f.x, 5)
