import getpass
import os
import shutil
import tempfile
from os import path as _p

import sh

from .pyshutil import compile_shargs


def __build(dockerfile, fg=False):
    tmpdir = tempfile.TemporaryDirectory()

    shutil.copyfile(dockerfile, _p.join(tmpdir.name, 'Dockerfile'))

    iidfile = _p.join(tmpdir.name, '__iid')
    sh.docker.build(tmpdir.name, iidfile=iidfile, _fg=fg)

    with open(iidfile, 'r') as f:
        return f.read()


def __create(image_id: str, commands: str, volumes=None):
    tmpdir = tempfile.TemporaryDirectory()

    cidfile = _p.join(tmpdir.name, '__cid')

    if not volumes:
        v_opts = []
    elif isinstance(volumes, str):
        v_opts = [f'-v={volumes}']
    elif isinstance(volumes, list):
        v_opts = [*map(lambda o: f'-v={o}', volumes)]
    else:
        raise Exception

    sh.docker.create(f'--cidfile={cidfile}',
                     *v_opts,
                     '-i',
                     '--rm',  # Automatically remove the container when it exits
                     image_id,
                     '/bin/bash',
                     c=commands,
                     )
    with open(cidfile, 'r') as f:
        return f.read()


def dsh(dockerfile: str,
        *args,
        _volumes=None,
        _root=False,
        _auto_remove=True,
        _verbose=False,
        _cwd=None,
        **kwargs,
        ):

    if not _cwd:
        _cwd = _p.realpath(_p.curdir)

    commands, shkwargs = compile_shargs(*args, **kwargs)

    commands = ' '.join(commands)

    image_id = __build(dockerfile, fg=_verbose)
    if not image_id:
        raise Exception('failed to build image')

    if _root:
        home = '/root'
        commands = f'cd {home} && {commands}'
    else:
        username = getpass.getuser()
        uid = os.getuid()
        gid = os.getgid()
        home = f'/home/{username}'

        commands = (
            f'if [ "$(id -u {username} > /dev/null 2>&1; echo $?)" == 0 ]; then userdel {username}; fi && '
            f'groupadd -g {gid} {username}; '
            f'useradd -l -u {uid} -g $(getent group {gid} | cut -d: -f1) {username} && '
            f'install -d -m 0755 -o {username} -g $(getent group {gid} | cut -d: -f1) {home} && '
            f'chown -R {uid}:{gid} {home} && '
            f'cd {home} && su {username} -c "/bin/bash -c \\"{commands}\\""'
        )

    # print(commands)

    container_id = __create(image_id, commands, f'{_cwd}:{home}:rw')
    if not container_id:
        raise Exception('failed to create container')

    fg = shkwargs['_fg'] if '_fg' in shkwargs else False

    if fg:
        return sh.docker.start(container_id, i=True, **shkwargs)
    else:
        return sh.docker.start(container_id, a=True, **shkwargs)
