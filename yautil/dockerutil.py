import getpass
import os
import sys
import tempfile
from os import path as _p
from typing import Union, List
# from deprecation import deprecated

import sh


def __build(build_context, fg=False, dockerfile_cmds_to_append: list = None, drop_priv=False, kvm=False):
    with open(_p.join(build_context, 'Dockerfile'), 'r') as f:
        dockerfile = f.read()

    if dockerfile_cmds_to_append:
        dockerfile += '\n{cmds}\n'.format(cmds='\n'.join(dockerfile_cmds_to_append))

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
            f'USER {uid}:{gid}'
            f'\n'
        )

    tmpdir = tempfile.TemporaryDirectory()

    iidfile = _p.join(tmpdir.name, '__iid')
    try:
        sh.docker.build('.',
                        f='-',
                        iidfile=iidfile,
                        _in=dockerfile,
                        _cwd=build_context,
                        _err_to_out=bool(fg),
                        _out=sys.stdout if bool(fg) else None,
                        )
    except sh.ErrorReturnCode as e:
        raise Exception(f'Failed to build a docker image with build context at {build_context}.\n'
                        f'STDOUT:\n'
                        f'{bytes(e.stdout).decode(sh.DEFAULT_ENCODING)}'
                        f'\n'
                        f'STDERR:\n'
                        f'{bytes(e.stderr).decode(sh.DEFAULT_ENCODING)}'
                        )
    except Exception:
        raise Exception(f'failed to build a docker image with build context at {build_context}.')

    with open(iidfile, 'r') as f:
        return f.read()


def docker_sh(
        docker_context: str,
        *docker_run_opts,
        root: bool = False,
        verbose: bool = False,
        volumes: Union[str, List[str]] = None,
        auto_remove: bool = True,
        dockerfile_cmds_to_append: list = None,
        kvm: bool = False,
        xforwarding: bool = False,
        net: str = 'bridge',
        _cwd: str = None,
) -> sh.Command:

    if (not docker_context) or (not _p.isdir(docker_context)):
        raise Exception('proper docker_context directory must be supplied')

    if os.getuid() == 0:
        root = True

    if verbose:
        print('Building a docker image...')
    image_id = __build(docker_context, fg=verbose, drop_priv=not root, kvm=kvm,
                       dockerfile_cmds_to_append=dockerfile_cmds_to_append)
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
        # run_opts.append('-v=/tmp/.X11-unix:/tmp/.X11-unix:rw')
        docker_run_opts.append(f'-v={_p.join(os.environ["HOME"], ".Xauthority")}:{_p.join(home, ".Xauthority")}')
        docker_run_opts.append(f'-eDISPLAY={os.environ["DISPLAY"]}')
        net = 'host'

    if kvm:
        docker_run_opts.append('--device=/dev/kvm')
        docker_run_opts.append('--group-add=kvm')
        # run_opts.append(f'-v=/etc/machine-id:/etc/machine-id:rw')
        # run_opts.append(f'-eQEMU_AUDIO_DRV=none')

    docker_run_opts.append(f'--net={net}')

    run = sh.docker.run.bake(
        *docker_run_opts,
        '-d=false',
        i=True,
        rm=bool(auto_remove),  # Automatically remove the container when it exits
        workdir=_p.realpath(_cwd) if _cwd else home,
    )

    return run.bake(image_id)
