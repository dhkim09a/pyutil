import glob
import re
import time
from typing import Union, List
import os
from os import path as _p

import sh

from yautil.mountutil.core import Mountable
from yautil.mountutil.block_dev_handle import BlockDevHandle


class QemuNbdHandle(BlockDevHandle):
    __img: str
    __dev: str = None
    __load_nbd = False

    def __init__(self, img: str):
        self.__img = img

    def find_free_nbd_dev(self):
        nbd_dev_avail = None
        modules, sizes, deps = zip(*[l.split(maxsplit=2) for l in str(sh.lsmod()).splitlines()])

        if 'nbd' not in modules:
            sh.sudo.modprobe('nbd', 'max_part=8', _fg=True)
            self.__load_nbd = True

        if not (nbd_devs := [*filter(lambda d: re.search(r'^nbd\d+$', d), os.listdir('/dev'))]):
            self.unmap()
            raise Exception('Failed to load nbd')

        for nbd_dev in nbd_devs:
            with open(fr'/sys/class/block/{nbd_dev}/size') as f:
                if f.read() == '0\n':
                    nbd_dev_avail = nbd_dev
                    break

        if not nbd_dev_avail:
            self.unmap()
            raise Exception('No nbd is available for mounting a qemu image')

        return f'/dev/{nbd_dev_avail}'

    def map(self) -> str:
        if self.base_dev:
            return self.base_dev

        dev = self.find_free_nbd_dev()

        assert dev

        try:
            sh.sudo('qemu-nbd', '--connect', dev, '-f', 'qcow2', self.__img, _fg=True)
            time.sleep(1)
        except sh.ErrorReturnCode_1:
            raise Exception(f'failed to open {self.__img}')

        self.__dev = dev

        return self.base_dev

    def unmap(self):
        if self.__dev:
            sh.sudo('qemu-nbd', '--disconnect', self.__dev, _fg=True)
            self.__dev = None

    @property
    def base_dev(self) -> str:
        return self.__dev

    @property
    def devs(self) -> List[str]:
        return [*filter(lambda d: re.search(fr'{self.base_dev}[a-zA-Z]', d), glob.glob('/dev/*'))]

    def __del__(self):
        self.unmap()


class QemuQcow2Image(Mountable):
    __nbd_ctx_: QemuNbdHandle = None
    __dev: str = None
    __partitions: List[Mountable] = None

    def __init__(self, file: str, dev: str = None):
        super().__init__(file)
        self.__dev = dev

    def _mount(self, file: str, mode: str, mount_point: str):
        assert self.__dev

        sh.sudo.mount(self.__dev, mount_point, _fg=True)

    def _umount(self, mount_point):
        sh.sudo.umount(mount_point, _fg=True)

    @classmethod
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        if file_cmd_out is None:
            return False
        return bool(re.search(r'^QEMU QCOW2 Image', file_cmd_out))

    @property
    def partitions(self) -> Union[list, None]:
        if self.__dev:
            return None

        if self.__partitions:
            return self.__partitions

        self.__nbd_ctx.map()
        self.__partitions = [QemuQcow2Image(self.name, dev=dev) for dev in self.__nbd_ctx.devs]

        return self.__partitions

    @property
    def __nbd_ctx(self) -> QemuNbdHandle:
        if not self.__nbd_ctx_:
            self.__nbd_ctx_ = QemuNbdHandle(self.name)
        return self.__nbd_ctx_
