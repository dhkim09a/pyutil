from os import path as _p
from unittest import TestCase

from yautil import dsh
from tempfile import TemporaryDirectory


class TestDocker(TestCase):
    tmpdir: TemporaryDirectory

    def setUp(self):
        self.tmpdir = TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_hello(self):
        dockerfile = _p.join(self.tmpdir.name, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')
        sout = str(dsh('echo', '-n', 'hello', _build_context=self.tmpdir.name))
        assert sout == 'hello'
