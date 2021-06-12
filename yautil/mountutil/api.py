from typing import Union

from .core import MountPoint, Mountable
from .types import MountableType, ArchiveType


def mount(file: Union[str, Mountable], mode: str = 'rw', mount_point: str = None, type: MountableType = MountableType.AUTO,
          **type_specific_args) -> MountPoint:

    if not isinstance(file, Mountable):
        print(file)
        file = type.instantiate(file, **type_specific_args)

    # if mountable._is_mounted:
    #     raise AlreadyMountedError('Already mounted')

    if file.partitions:
        raise Exception('Specify one of partitions.')

    mp = MountPoint(file, mode, mount_point)

    file._is_mounted = True
    file._mount(file.name, mode, mp.name)

    return mp


def extract(file: str, dest: str, type: ArchiveType = ArchiveType.AUTO):
    a = type.instantiate(file)

    a._extract(file, dest)


def archive(file: str, src: str, type: ArchiveType):
    if type == ArchiveType.AUTO:
        raise ValueError(type)

    a = type.instantiate(file)

    a._archive(file, src)
