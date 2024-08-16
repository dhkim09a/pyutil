import getpass
import os
import re
import sys
import tempfile
from os import path as _p
from typing import Literal, Union, List, Optional
# from deprecation import deprecated

import sh


class AuthorizationError(Exception):
    pass


def __build(build_context,
            dockerfile,
            fg=False,
            dockerfile_cmds_to_append: list[str] | None = None,
            drop_priv=False,
            kvm=False,
            builder: Optional[str] = None,
            ):
    with open(_p.join(build_context, dockerfile), 'r') as f:
        dockerfile = f.read()

    if kvm:
        import grp
        kvm_gid = grp.getgrnam('kvm').gr_gid
        dockerfile += (
            # f'RUN apt-get install -y qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils'
            # f'\n'
            # f'RUN groupmod -g {kvm_gid} kvm'
            f'\n'
            f'RUN groupadd -g {kvm_gid} kvm'
            f'\n'
        )

    # if xforwarding:
    #     dockerfile += (
    #         f'\n'
    #         f'RUN apt-get install -y xinit xserver-xorg-core --no-install-recommends --no-install-suggests'
    #         f'\n'
    #     )

    if drop_priv:
        username = getpass.getuser()
        uid = os.getuid()
        gid = os.getgid()
        home = f'/home/{username}'
        groupname = f'$(getent group {gid} | cut -d: -f1)'

        dockerfile += (
            f'\n'
            f'SHELL ["/bin/bash", "-c"]'
            f'\n'
            f'RUN if [ "$(id -u {username} > /dev/null 2>&1; echo $?)" == 0 ]; then userdel {username}; fi'
            f' && groupadd -g {gid} {username}'
            f' ;  useradd -l -u {uid} -g {groupname} {"-G kvm" if kvm else ""} {username}'
            f' && install -d -m 0755 -o {username} -g {groupname} {home}'
            f'\n'
            f'SHELL ["/bin/sh", "-c"]'
            f'\n'
            f'ENV HOME={home}'
            f'\n'
            f'ENV USER={username}'
            f'\n'
        )

    if dockerfile_cmds_to_append:
        dockerfile += '\n{cmds}\n'.format(cmds='\n'.join(dockerfile_cmds_to_append))

    if drop_priv:
        dockerfile += (
            f'\n'
            f'USER {uid}:{gid}'
            f'\n'
        )

    tmpdir = tempfile.TemporaryDirectory()

    iidfile = _p.join(tmpdir.name, '__iid')
    try:
        sh.docker.build('.', # type: ignore
                        f='-',
                        iidfile=iidfile,
                        builder=builder if builder else False,
                        network='host',
                        _in=dockerfile,
                        _cwd=build_context,
                        # _err_to_out=bool(fg),
                        _err_to_out=True,
                        _out=sys.stderr if bool(fg) else None,
                        # _err=sys.stderr if bool(fg) else None,
                        _tee='out',
                        _env={
                            'DOCKER_BUILDKIT': '1',
                            'PATH': os.environ['PATH'],
                        },
                        )
    except sh.ErrorReturnCode as e:
        sout = bytes(e.stdout).decode(sh.DEFAULT_ENCODING)

        m = re.search(r'^ERROR: (?P<msg>.*)$', sout, re.M)

        if m and (msg := m.groupdict().get('msg', None)):
            if 'failed to authorize' in msg:
                raise AuthorizationError(msg)

        raise Exception(
            f'Failed to build a docker image with build context at {build_context}. ({e.exit_code})\n'
            f'---\n'
            f'{sout}'
        )
    except Exception as e:
        raise Exception(f'Internal docker build error: {e}')

    with open(iidfile, 'r') as f:
        return f.read()


def docker_sh(
        docker_context: str,
        *docker_run_opts,
        root: bool = False,
        verbose: bool = False,
        volumes: str | list[str] | None = None,
        auto_remove: bool = True,
        dockerfile_cmds_to_append: list[str] | None = None,
        kvm: bool = False,
        xforwarding: bool = False,
        net: str = 'bridge',
        dockerfile: str = 'Dockerfile',
        gpus: Union[str, Literal['all', False]] = False,
        builder: Optional[str] = None,
        _cwd: str | None = None,
) -> sh.Command:

    if (not docker_context) or (not _p.isdir(docker_context)):
        raise Exception('proper docker_context directory must be supplied')

    if os.getuid() == 0:
        root = True

    if verbose:
        print('Building a docker image...')
    image_id = __build(docker_context, dockerfile, fg=verbose, drop_priv=not root, kvm=kvm,
                       dockerfile_cmds_to_append=dockerfile_cmds_to_append, builder=builder)
    if not image_id:
        raise Exception('failed to build image')

    if root:
        home = '/root'
    else:
        username = getpass.getuser()
        home = f'/home/{username}'

    if docker_run_opts is None:
        docker_run_opts = []
    else:
        docker_run_opts = list(docker_run_opts)

    if not volumes:
        pass
    elif isinstance(volumes, str):
        docker_run_opts += [f'-v={volumes}']
    elif isinstance(volumes, list):
        docker_run_opts += [*map(lambda o: f'-v={o}', volumes)]
    else:
        raise Exception

    if xforwarding:
        docker_run_opts.append('-v=/tmp/.X11-unix:/tmp/.X11-unix:rw')
        docker_run_opts.append(f'-v={_p.join(os.environ["HOME"], ".Xauthority")}:{_p.join(home, ".Xauthority")}')
        docker_run_opts.append(f'-eDISPLAY={os.environ["DISPLAY"]}')
        docker_run_opts.append(f'--privileged')
        net = 'host'

    if kvm:
        docker_run_opts.append('--device=/dev/kvm')
        docker_run_opts.append('--group-add=kvm')
        docker_run_opts.append(f'-v=/etc/machine-id:/etc/machine-id:rw')
        # docker_run_opts.append(f'-eQEMU_AUDIO_DRV=none')

    docker_run_opts.append(f'--net={net}')

    run = sh.docker.run.bake( # type: ignore
        *docker_run_opts,
        '-d=false',
        i=True,
        t=True,
        rm=bool(auto_remove),  # Automatically remove the container when it exits
        workdir=_p.realpath(_cwd) if _cwd else home,
        gpus=gpus,
    )

    return run.bake(image_id)
