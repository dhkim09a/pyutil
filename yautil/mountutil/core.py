import os
import re
import shutil
from tempfile import TemporaryDirectory
from typing import Union
from os import path as _p

import sh


class AlreadyMountedError(Exception):
    pass


class NotMountedError(Exception):
    pass


def _empty_dir(dir: str):
    for filename in os.listdir(dir):
        file_path = os.path.join(dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


class MountPoint:
    __mountable: None
    __mode: str
    __mount_point: str
    __tmpdir: TemporaryDirectory

    def __init__(self, mountable, mode: str, mount_point: str):
        self.__mountable = mountable
        self.__mode = mode

        if not mount_point:
            self.__tmpdir = TemporaryDirectory(prefix='yautil-mountutil-')
            mount_point = self.__tmpdir.name

        self.__mount_point = mount_point

    @property
    def name(self) -> str:
        return self.__mount_point

    def umount(self):
        if not self.__mountable._is_mounted:
            raise NotMountedError('Not mounted')

        self.__mountable._is_mounted = False
        return self.__mountable._umount(self.name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.umount()
        except NotMountedError:
            pass

    def __del__(self):
        try:
            self.umount()
        except NotMountedError:
            pass


class Mountable:
    __file: str
    _is_mounted: bool = False

    def __init__(self, file: str, **kwargs):
        if type(self) == Mountable:
            if not _p.isfile(file):
                raise FileNotFoundError(file)

            if not (cls := self.__resolve_cls(file)):
                raise Exception('unsupported file type ' + file + ' ' + str(sh.file(file)))
            self.__class__ = cls
            self.__init__(file, **kwargs)

        assert type(self) != Mountable
        assert isinstance(self, Mountable)

        self.__file = file

    def _mount(self, file: str, mode: str, mount_point: str):
        raise NotImplementedError

    def _umount(self, mount_point):
        raise NotImplementedError

    @classmethod
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        raise NotImplementedError

    @property
    def partitions(self) -> Union[list, None]:
        return None

    @property
    def name(self) -> str:
        return self.__file

    @classmethod
    def __resolve_cls(cls, file: str):
        from .types import MountableType

        desc = str(sh.file(file, brief=True)).strip()

        for typ in MountableType:
            if typ == MountableType.AUTO:
                continue
            mountable_cls = typ.value
            if mountable_cls._ismountable(file, desc):
                return mountable_cls


class Archive(Mountable):
    ro: bool = False

    def _extract(self, file: str, target_dir: str):
        raise NotImplementedError

    def _archive(self, file: str, source_dir: str):
        raise NotImplementedError

    def _mount(self, file: str, mode: str, mount_point: str):
        if mode == 'r':
            self.ro = True
        elif mode == 'rw':
            self.ro = False
        else:
            raise ValueError('mode must be either \'r\' or \'rw\'')

        self._extract(file, mount_point)

    def _umount(self, mount_point):
        if not self.ro:
            self._archive(self.name, mount_point)

        _empty_dir(mount_point)
