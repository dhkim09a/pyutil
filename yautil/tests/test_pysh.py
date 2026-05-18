import os
from tempfile import NamedTemporaryFile
from unittest import TestCase

import sh

from yautil.pysh import compile_shargs, get_cmd_args, source


class TestGetCmdArgs(TestCase):
    def test_returns_path_only_for_unbaked(self):
        cmd = sh.Command('/bin/ls')
        args = get_cmd_args(cmd)
        self.assertEqual(args, ['/bin/ls'])

    def test_includes_baked_args(self):
        cmd = sh.Command('/bin/ls').bake('-l', '-a')
        args = get_cmd_args(cmd)
        self.assertIn('/bin/ls', args)
        self.assertIn('-l', args)
        self.assertIn('-a', args)


class TestCompileShargs(TestCase):
    def test_positional(self):
        cmdargs, shargs = compile_shargs('foo', 'bar')
        self.assertIn('foo', cmdargs)
        self.assertIn('bar', cmdargs)
        self.assertEqual(shargs, {})

    def test_kwarg_becomes_flag(self):
        cmdargs, shargs = compile_shargs('foo', verbose=True)
        self.assertIn('foo', cmdargs)
        self.assertIn('--verbose', cmdargs)

    def test_underscore_kwarg_is_sh_arg(self):
        cmdargs, shargs = compile_shargs('foo', _tty_out=False)
        self.assertEqual(cmdargs, ['foo'])
        self.assertIn('_tty_out', shargs)
        self.assertFalse(shargs['_tty_out'])


class TestSource(TestCase):
    def test_source_sets_env_vars(self):
        with NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
            f.write('export MY_VAR=hello\n')
            script_path = f.name
        try:
            env = source(script_path)
            self.assertEqual(env.get('MY_VAR'), 'hello')
        finally:
            os.unlink(script_path)

    def test_source_with_inline_command(self):
        with NamedTemporaryFile('w', suffix='.sh', delete=False) as f:
            f.write('export A=1\n')
            script_path = f.name
        try:
            env = source(script_path, cmd='export B=2')
            self.assertEqual(env.get('A'), '1')
            self.assertEqual(env.get('B'), '2')
        finally:
            os.unlink(script_path)
