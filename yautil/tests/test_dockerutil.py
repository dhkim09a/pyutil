import os
from os import path as _p
from unittest import TestCase

from yautil import dsh
from tempfile import TemporaryDirectory

from yautil.dockerutil import docker_sh


class TestDocker(TestCase):
    tmpdir: TemporaryDirectory

    def setUp(self):
        self.tmpdir = TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_hello(self):
        ctx = _p.join(self.tmpdir.name, 'test_hello')
        os.makedirs(ctx, exist_ok=True)

        dockerfile = _p.join(ctx, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')

        sout = str(dsh('echo', '-n', 'hello', _build_context=ctx))
        assert sout == 'hello'

        sout = str(dsh('pwd', _build_context=ctx))
        assert sout.startswith('/home/')

        sout = str(dsh('pwd', _build_context=ctx, _root=True))
        assert sout == '/root\n'

    def test_docker_sh(self):
        ctx = _p.join(self.tmpdir.name, 'test_v2')
        os.makedirs(ctx, exist_ok=True)

        dockerfile = _p.join(ctx, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')

        c = docker_sh(ctx)
        rc = docker_sh(ctx, root=True)

        assert str(c.echo('-n', 'hello')) == 'hello'

        assert str(c.pwd()).startswith('/home/')

        assert str(rc.pwd()).strip() == '/root'

        assert int(str(c.id(u=True)).strip()) != 0

        assert int(str(rc.id(u=True)).strip()) == 0
