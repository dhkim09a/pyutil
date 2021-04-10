import getpass
import os
import tempfile
from os import path as _p

import sh

from .pyshutil import compile_shargs


def __build(build_context, fg=False):
    tmpdir = tempfile.TemporaryDirectory()

    iidfile = _p.join(tmpdir.name, '__iid')
    try:
        sh.docker.build(build_context, iidfile=iidfile, _fg=fg)
    except Exception:
        raise Exception(f'failed to build a docker image with build context at {build_context}')

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


def dsh(*args,
        _volumes=None,
        _root=False,
        _auto_remove=True,
        _verbose=False,
        _cwd=None,
        _build_context=None,
        **kwargs,
        ):

    if (not _build_context) or (not _p.isdir(_build_context)):
        raise Exception('proper _build_context directory must be supplied')

    if not _cwd:
        _cwd = _p.curdir

    _cwd = _p.realpath(_cwd)

    commands, shkwargs = compile_shargs(*args, **kwargs)

    commands = ' '.join(commands)

    if _verbose:
        print('Building a docker image...')
    image_id = __build(_build_context, fg=_verbose)
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
            # f'chown -R {uid}:{gid} {home} && '
            f'cd {home} && su {username} -c "/bin/bash -c \\"{commands}\\""'
        )

    # print(commands)

    if _verbose:
        print('Creating a docker container...')
    container_id = __create(image_id, commands, f'{_cwd}:{home}:rw')
    if not container_id:
        raise Exception('failed to create container')

    fg = shkwargs['_fg'] if '_fg' in shkwargs else False

    if _verbose:
        print('Starting the docker container...')
    if fg:
        return sh.docker.start(container_id, i=True, **shkwargs)
    else:
        return sh.docker.start(container_id, a=True, **shkwargs)
