import re
from tempfile import TemporaryDirectory
from typing import Union
from os import path as _p

import sh


class Mount:
    __mountable: None
    __mode: str
    __mount_point: str
    __tmpdir: TemporaryDirectory

    def __init__(self, mountable, mode: str, mount_point: str):
        self.__mountable = mountable
        self.__mode = mode

        if not mount_point:
            self.__tmpdir = TemporaryDirectory()
            mount_point = self.__tmpdir.name

        self.__mount_point = mount_point

    @property
    def name(self) -> str:
        return self.__mount_point

    def umount(self):
        return self.__mountable._umount(self.name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.umount()


class Mountable:
    __file: str

    def __init__(self, file: str):
        if not _p.isfile(file):
            raise FileNotFoundError(file)

        if type(self) == Mountable:
            if not (cls := self.__resolve_cls(file)):
                raise Exception('unsupported file type')
            self.__class__ = cls

        assert type(self) != Mountable
        assert isinstance(self, Mountable)

        self.__file = file

    def _mount(self, file: str, mode: str, mount_point: str):
        raise NotImplementedError

    def _umount(self, mount_point):
        raise NotImplementedError

    @classmethod
    def _pattern(cls) -> str:
        raise NotImplementedError

    @property
    def volumes(self) -> Union[list, None]:
        return None

    @property
    def name(self) -> str:
        return self.__file

    @classmethod
    def __resolve_cls(cls, file: str):
        from .mountable_file_type import MountableFileType

        desc = str(sh.file(file, brief=True)).strip()

        for typ in MountableFileType:
            if re.search(typ.value._pattern(), desc):
                return typ.value


def mount(mountable: Mountable, mode: str = 'rw', mount_point: str = None) -> Mount:
    if mountable.volumes:
        raise Exception('Specify one of volumes.')

    m = Mount(mountable, mode, mount_point)

    mountable._mount(mountable.name, mode, m.name)

    return m


def test():
    mountable = Mountable('/file')

    with mount(mountable, 'rw') as m:
        m.name
        pass

    m = mount(mountable, 'rw')
    m.name

    m.umount()
