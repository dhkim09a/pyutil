import getpass
import os
import sys
import tempfile
from os import path as _p
from typing import Union, List
# from deprecation import deprecated

import sh


def __build(build_context, fg=False, drop_priv=False):
    dockerfile = None

    if drop_priv:
        username = getpass.getuser()
        uid = os.getuid()
        gid = os.getgid()
        home = f'/home/{username}'
        groupname = f'$(getent group {gid} | cut -d: -f1)'

        with open(_p.join(build_context, 'Dockerfile'), 'r') as f:
            dockerfile = f.read()
        dockerfile += (
            f'\n'
            f'RUN if [ "$(id -u {username} > /dev/null 2>&1; echo $?)" == 0 ]; then userdel {username}; fi'
            f' && groupadd -g {gid} {username}'
            f' ;  useradd -l -u {uid} -g {groupname} {username}'
            f' && install -d -m 0755 -o {username} -g {groupname} {home}'
            f'\n'
            f'ENV HOME={home}'
            f'\n'
            f'ENV USER={username}'
            f'\n'
            f'USER {uid}:{gid}'
        )

    tmpdir = tempfile.TemporaryDirectory()

    iidfile = _p.join(tmpdir.name, '__iid')
    try:
        sh.docker.build('.',
                        f='-' if bool(drop_priv) else False,
                        iidfile=iidfile,
                        _in=dockerfile if bool(drop_priv) else None,
                        _cwd=build_context,
                        _err_to_out=bool(fg),
                        _out=sys.stdout if bool(fg) else None,
                        )
    except Exception:
        raise Exception(f'failed to build a docker image with build context at {build_context}')

    with open(iidfile, 'r') as f:
        return f.read()


def docker_sh(
        docker_context: str,
        root: bool = False,
        verbose: bool = False,
        volumes: Union[str, List[str]] = None,
        auto_remove: bool = True,
) -> sh.Command:

    if (not docker_context) or (not _p.isdir(docker_context)):
        raise Exception('proper docker_context directory must be supplied')

    if verbose:
        print('Building a docker image...')
    image_id = __build(docker_context, fg=verbose, drop_priv=not root)
    if not image_id:
        raise Exception('failed to build image')

    if root:
        home = '/root'
    else:
        username = getpass.getuser()
        home = f'/home/{username}'

    if not volumes:
        v_opts = []
    elif isinstance(volumes, str):
        v_opts = [f'-v={volumes}']
    elif isinstance(volumes, list):
        v_opts = [*map(lambda o: f'-v={o}', volumes)]
    else:
        raise Exception

    run = sh.docker.run.bake(
        *v_opts,
        '-d=false',
        i=True,
        rm=bool(auto_remove),  # Automatically remove the container when it exits
        workdir=home,
    )

    return run.bake(image_id)
