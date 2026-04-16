from typing import Literal
import re

import sh

from ..core import Mountable
from ..udisksctl import udisksctl, udisksctl_losetup, udisksctl_mount


class UDisksCtlCtx:
    __dev: str | None = None
    __mount_point: str | None = None

    def mount(self, image: str, offset: int = 0) -> str:
        self.__dev = udisksctl_losetup(image, offset=offset)

        self.__mount_point = udisksctl_mount(self.__dev)
        return self.__mount_point

    def umount(self) -> None:
        if self.__mount_point:
            udisksctl('unmount', b=self.__dev)
            self.__mount_point = None

        if self.__dev:
            udisksctl('loop-delete', b=self.__dev)
            self.__dev = None


class LinuxDiskImage(Mountable):
    __offset: int
    __lomode: Literal['mount', 'losetup', 'udisksctl'] = 'mount'
    __mntmode: Literal['mount', 'udisksctl'] = 'mount'
    __dev: str | None = None

    def __init__(
        self,
        file: str,
        offset: int = 0,
        lomode: Literal['mount', 'losetup', 'udisksctl'] = 'mount',
        mntmode: Literal['mount', 'udisksctl'] = 'mount'
    ):
        super().__init__(file)

        if lomode not in ['mount', 'losetup', 'udisksctl']:
            raise ValueError

        if mntmode not in ['mount', 'udisksctl']:
            raise ValueError

        self.__offset = offset
        self.__lomode = lomode
        self.__mntmode = mntmode

    def _mount(self, file: str, mode: str, mount_point: str) -> str:
        if self.__lomode == 'mount':
            sh.sudo.mount(file, mount_point, o=f'offset={self.__offset}', _fg=True)
            return mount_point
        elif self.__lomode == 'losetup':
            self.__dev = str(sh.losetup(f=True)) # type: ignore
            sh.sudo.losetup(self.__dev, file, _fg=True)
        elif self.__lomode == 'udisksctl':
            self.__dev = udisksctl_losetup(file, offset=self.__offset)
        else:
            raise ValueError

        # print('mount: ' + self.__dev)

        assert self.__dev

        if self.__mntmode == 'mount':
            sh.sudo.mount(self.__dev, mount_point, o=f'loop,offset={self.__offset}', _fg=True)
            return mount_point
        elif self.__mntmode == 'udisksctl':
            actual_mount_point = udisksctl_mount(self.__dev, opts=mode)
            return actual_mount_point
        else:
            raise ValueError

    def _umount(self, mount_point: str) -> None:
        if self.__lomode == 'mount':
            sh.sudo.umount(mount_point, _fg=True)
            return

        if self.__mntmode == 'mount':
            # when mounting a loop device, mount command changes the loop device. hence, self.__dev is invalid at here
            # sh.sudo.umount(self.__dev, _fg=True)
            sh.sudo.umount(mount_point, _fg=True)
        elif self.__mntmode == 'udisksctl':
            udisksctl('unmount', b=self.__dev)
        else:
            raise ValueError

        if self.__lomode == 'losetup':
            raise NotImplementedError
        elif self.__lomode == 'udisksctl':
            udisksctl('loop-delete', b=self.__dev)

    @classmethod
    def _ismountable(cls, path: str | None = None, file_cmd_out: str | None = None) -> bool:
        if file_cmd_out is None:
            return False
        return (
            bool(re.search(r'^Linux[^,]*filesystem data', file_cmd_out))
            or bool(re.search(r'\b(FAT|FAT32)\b', file_cmd_out))
        )
