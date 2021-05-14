import time

import sh as sh

from . import Mountable


class Qcow2Image(Mountable):
    def _mount(self, file: str, mode: str, mount_point: str):
        sh.nbdfuse(mount_point, '--socket-activation', 'qemu-nbd', file, _bg=True)
        time.sleep(1)

    def _umount(self, mount_point):
        sh.fusermount3('-uz', mount_point)

    @classmethod
    def _pattern(cls) -> str:
        return r'QCOW2'
