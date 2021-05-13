import glob
from typing import Union

import sh

from .mountable import Mountable


class QemuNbdContext:
    __img: str
    __dev: str = None
    __load_nbd = False

    def __init__(self, img: str):
        self.__img = img

    def map(self) -> str:
        if self.dev:
            return self.dev

        nbd_id = 0
        modules, sizes, deps = zip(*[l.split(maxsplit=2) for l in str(sh.lsmod()).splitlines()])

        if 'nbd' not in modules:
            sh.sudo.modprobe('nbd', 'max_part=8', _fg=True)
            self.__load_nbd = True

        if (num_nbd := len(glob.glob('/dev/nbd*'))) == 0:
            self.unmap()
            raise Exception('Failed to load nbd')

        for nbd_id in range(num_nbd + 1):
            if nbd_id == num_nbd:
                self.unmap()
                raise Exception('No nbd is available for mounting a qemu image')

            with open(fr'/sys/class/block/nbd{nbd_id}/size') as f:
                if f.read() == '0\n':
                    break

        fmt = 'raw'
        if self.__img.endswith(r'.qcow2'):
            fmt = 'qcow2'

        dev = f'/dev/nbd{nbd_id}'

        try:
            sh.sudo('qemu-nbd', '--connect', dev, '-f', fmt, self.__img, _fg=True)
        except sh.ErrorReturnCode_1:
            raise Exception(f'failed to open {self.__img}')

        self.__dev = dev

        return self.dev

    def unmap(self):
        if self.__dev:
            sh.sudo('qemu-nbd', '--disconnect', self.__dev, _fg=True)
            self.__dev = None

        # if self.__load_nbd:
        #     sh.sudo.rmmod('nbd', _fg=True)

    @property
    def dev(self) -> str:
        return self.__dev

    def __enter__(self):
        if not self.__dev:
            self.map()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unmap()

    def __del__(self):
        self.unmap()


class QemuQcow2Image(Mountable):
    __nbd_ctx_: QemuNbdContext = None
    __dev: str = None

    def __init__(self, file: str, dev: str = None):
        super().__init__(file)
        self.__dev = dev

    def _mount(self, file: str, mode: str, mount_point: str):
        assert self.__dev

        sh.sudo.mount(self.__dev, mount_point, _fg=True)

    def _umount(self, mount_point):
        sh.sudo.umount(mount_point, _fg=True)

    @classmethod
    def _pattern(cls) -> str:
        pass

    @property
    def volumes(self) -> Union[list, None]:
        if self.__dev:
            return None

        devs = glob.glob(self.__nbd_ctx.dev + '*')
        return [QemuQcow2Image(self.name, dev=dev) for dev in filter(lambda d: d != self.__nbd_ctx.dev, devs)]

    @property
    def __nbd_ctx(self) -> QemuNbdContext:
        if not self.__nbd_ctx_:
            self.__nbd_ctx_ = QemuNbdContext(self.name)
        return self.__nbd_ctx_
