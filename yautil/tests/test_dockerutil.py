import os
from os import path as _p
from unittest import TestCase

from yautil import docker_sh
from tempfile import TemporaryDirectory


class TestDocker(TestCase):
    tmpdir: TemporaryDirectory

    def setUp(self):
        self.tmpdir = TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    # def test_hello(self):
    #     uid = os.getuid()
    #     gid = os.getgid()
    #
    #     ctx = _p.join(self.tmpdir.name, 'test_hello')
    #     os.makedirs(ctx, exist_ok=True)
    #
    #     dockerfile = _p.join(ctx, 'Dockerfile')
    #     with open(dockerfile, 'w+') as f:
    #         f.write('FROM ubuntu')
    #
    #     assert str(dsh('echo', 'hello', _build_context=ctx)).strip() == 'hello'
    #
    #     assert int(str(dsh('id -u', _build_context=ctx)).strip()) == uid
    #
    #     assert int(str(dsh('id -g', _build_context=ctx)).strip()) == gid
    #
    #     assert int(str(dsh('id -u', _build_context=ctx, _root=True)).strip()) == '0'
    #
    #     assert int(str(dsh('id -g', _build_context=ctx, _root=True)).strip()) == '0'

    def test_docker_sh(self):
        uid = os.getuid()
        gid = os.getgid()

        ctx = _p.join(self.tmpdir.name, 'test_docker_sh')
        os.makedirs(ctx, exist_ok=True)

        dockerfile = _p.join(ctx, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')

        c = docker_sh(ctx, root=True)

        assert str(c.echo('-n', 'hello')) == 'hello'

        assert int(str(c.id(u=True)).strip()) == 0

        assert int(str(c.id(g=True)).strip()) == 0

    def test_priv_drop(self):
        uid = os.getuid()
        gid = os.getgid()

        ctx = _p.join(self.tmpdir.name, 'test_priv_drop')
        os.makedirs(ctx, exist_ok=True)

        dockerfile = _p.join(ctx, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')

        c = docker_sh(ctx)

        assert str(c.echo('-n', 'hello')) == 'hello'

        assert int(str(c.id(u=True)).strip()) == uid

        assert int(str(c.id(g=True)).strip()) == gid

    def test_verbose(self):
        uid = os.getuid()
        gid = os.getgid()

        ctx = _p.join(self.tmpdir.name, 'test_verbose')
        os.makedirs(ctx, exist_ok=True)

        dockerfile = _p.join(ctx, 'Dockerfile')
        with open(dockerfile, 'w+') as f:
            f.write('FROM ubuntu')

        c = docker_sh(ctx, verbose=True)

        assert str(c.echo('-n', 'hello')) == 'hello'

        assert int(str(c.id(u=True)).strip()) == uid

        assert int(str(c.id(g=True)).strip()) == gid
