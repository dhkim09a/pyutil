import re

import sh

from ..core import Mountable
from ..udisksctl import udisksctl, udisksctl_losetup, udisksctl_mount


class UDisksCtlCtx:
    __dev: str = None
    __mount_point: str = None

    def mount(self, image: str):
        self.__dev = udisksctl_losetup(image)

        self.__mount_point = udisksctl_mount(self.__dev)

    def umount(self):
        if self.__mount_point:
            udisksctl('unmount', b=self.__dev)
            self.__mount_point = None

        if self.__dev:
            udisksctl('loop-delete', b=self.__dev)
            self.__dev = None


class LinuxDiskImage(Mountable):
    __offset: int
    __lomode: str = 'mount'
    __mntmode: str = 'mount'
    __dev: str = None

    def __init__(self, file: str, offset=0, lomode='mount', mntmode='mount'):
        super().__init__(file)

        if not (lomode == 'mount' or lomode == 'udisksctl' or lomode == 'losetup'):
            raise ValueError

        # dhkim: TODO
        # if not (mntmode == 'mount' or mntmode == 'udisksctl'):
        if not (mntmode == 'mount'):
            raise ValueError

        self.__offset = offset
        self.__lomode = lomode
        self.__mntmode = mntmode

    def _mount(self, file: str, mode: str, mount_point: str):
        if self.__lomode == 'mount':
            sh.sudo.mount(file, mount_point, o=f'offset={self.__offset}', _fg=True)
            return
        elif self.__lomode == 'losetup':
            self.__dev = str(sh.losetup(f=True))
            sh.sudo.losetup(self.__dev, file, _fg=True)
        elif self.__lomode == 'udisksctl':
            self.__dev = udisksctl_losetup(file)
        else:
            raise ValueError

        print('mount: ' + self.__dev)

        assert self.__dev

        if self.__mntmode == 'mount':
            sh.sudo.mount(self.__dev, mount_point, o=f'loop,offset={self.__offset}', _fg=True)
        elif self.__mntmode == 'udisksctl':
            mount_point = udisksctl_mount(self.__dev)
        else:
            raise ValueError

    def _umount(self, mount_point):
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
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        if file_cmd_out is None:
            return False
        return bool(re.search(r'^Linux[^,]*filesystem data', file_cmd_out))
