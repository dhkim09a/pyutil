import argparse
import io
from contextlib import redirect_stderr
from unittest import TestCase

from yautil.argparse import (
    ChoiceComb,
    OverridingAppendAction,
    SmartAppendAction,
    SplitAppendAction,
    WarningAction,
)


class TestOverridingAppendAction(TestCase):
    def test_first_call_clears_default(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=OverridingAppendAction, default=['preset'])
        args = parser.parse_args(['--x', 'a', '--x', 'b'])
        self.assertEqual(args.x, ['a', 'b'])

    def test_default_kept_when_no_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=OverridingAppendAction, default=['preset'])
        args = parser.parse_args([])
        self.assertEqual(args.x, ['preset'])


class TestSplitAppendAction(TestCase):
    def test_comma_split(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SplitAppendAction, default=[])
        args = parser.parse_args(['--x', 'a,b,c'])
        self.assertEqual(args.x, ['a', 'b', 'c'])

    def test_multi_invocations(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SplitAppendAction, default=[])
        args = parser.parse_args(['--x', 'a,b', '--x', 'c'])
        self.assertEqual(args.x, ['a', 'b', 'c'])

    def test_overrides_default(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SplitAppendAction, default=['preset'])
        args = parser.parse_args(['--x', 'a'])
        self.assertEqual(args.x, ['a'])


class TestChoiceComb(TestCase):
    def test_includes_all_metaopt(self):
        cc = ChoiceComb(['x', 'y'])
        self.assertIn('all', cc)

    def test_contains_single(self):
        cc = ChoiceComb(['x', 'y'])
        self.assertIn('x', cc)
        self.assertIn('y', cc)

    def test_contains_comma_combination(self):
        cc = ChoiceComb(['x', 'y', 'z'])
        # all parts must be members
        self.assertIn('x,y', cc)
        self.assertNotIn('x,bogus', cc)

    def test_no_opts_excludes_negations(self):
        cc = ChoiceComb(['x'], no_opts=False)
        self.assertNotIn('no-x', list.__iter__(cc))

    def test_no_opts_includes_negations(self):
        cc = ChoiceComb(['x'], no_opts=True)
        self.assertIn('no-x', list(cc))


class TestSmartAppendAction(TestCase):
    def test_basic_append(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SmartAppendAction, default=[])
        args = parser.parse_args(['--x', 'a'])
        self.assertEqual(args.x, ['a'])

    def test_comma_split(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SmartAppendAction, default=[])
        args = parser.parse_args(['--x', 'a,b,c'])
        self.assertEqual(args.x, ['a', 'b', 'c'])

    def test_all_expands_choices(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SmartAppendAction,
                            choices=['foo', 'bar', 'baz'], default=[])
        args = parser.parse_args(['--x', 'all'])
        self.assertEqual(sorted(args.x), ['bar', 'baz', 'foo'])

    def test_invalid_choice_raises(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SmartAppendAction,
                            choices=['foo', 'bar'], default=[])
        # argparse intercepts the ValueError and turns it into SystemExit
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                parser.parse_args(['--x', 'invalid'])

    def test_overrides_default_on_first_call(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--x', action=SmartAppendAction, default=['preset'])
        args = parser.parse_args(['--x', 'a'])
        self.assertEqual(args.x, ['a'])


class TestWarningAction(TestCase):
    def test_basic_parse(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-W', action=WarningAction,
                            choices=['unused', 'shadow'])
        args = parser.parse_args(['-W', 'unused'])
        self.assertIn('unused', list(args.W))

    def test_comma_separated(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-W', action=WarningAction,
                            choices=['a', 'b'])
        args = parser.parse_args(['-W', 'a,b'])
        self.assertIn('a', list(args.W))
        self.assertIn('b', list(args.W))

    def test_all_sets_attributes_true(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-W', action=WarningAction,
                            choices=['foo', 'bar'])
        args = parser.parse_args(['-W', 'all'])
        self.assertTrue(args.W.foo)
        self.assertTrue(args.W.bar)

    def test_no_prefix_disables_attribute(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-W', action=WarningAction,
                            choices=['foo'])
        args = parser.parse_args(['-W', 'all', '-W', 'no-foo'])
        self.assertFalse(args.W.foo)
