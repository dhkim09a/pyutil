import time

import sh as sh

from ..core import Mountable


class Qcow2Image(Mountable):
    def _mount(self, file: str, mode: str, mount_point: str):
        sh.nbdfuse(mount_point, '--socket-activation', 'qemu-nbd', file, _bg=True)
        time.sleep(1)

    def _umount(self, mount_point):
        # use '-uz' to force unmount https://stackoverflow.com/a/25986155/3836385
        sh.fusermount3('-uz', mount_point)

    @classmethod
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        if file_cmd_out is None:
            return False
        return bool(r'QCOW2' in file_cmd_out)
