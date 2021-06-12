import re
from typing import Union, List

import sh

from ..core import Mountable
from .linux_disk_image import LinuxDiskImage


class DiskImage(Mountable):
    __partitions: List[Mountable] = None
    __in_qcow2: bool = False

    def __init__(self, file: str, in_qcow2: bool = False):
        super().__init__(file)
        self.__in_qcow2 = in_qcow2

    def __iter_partitions(self):
        rc = sh.fdisk(self.name, l=True, o='Start,End,Sectors,Type', color='never', _iter=True)
        sector_size = 512

        for line in rc:
            line = str(line).strip()

            if m := re.search(r'Units:.*?(?P<sector_size>\d+) bytes', line):
                sector_size = int(m['sector_size'])

            if not line:
                break

        for line in rc:
            line = str(line).strip()

            try:
                # be aware that 'type' may include spaces.
                start, end, sectors, type = line.split(maxsplit=3)
                start, end, sectors = (int(i) for i in [start, end, sectors])
            except ValueError:
                # skip column titles
                continue

            assert end - start + 1 == sectors
            # print(f'start: {start}, sector_size: {sector_size}')

            yield start * sector_size, sectors * sector_size, type.strip()

    def _mount(self, file: str, mode: str, mount_point: str):
        assert False

    def _umount(self, mount_point):
        assert False

    @classmethod
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        if file_cmd_out is None:
            return False
        return r'boot sector' in file_cmd_out

    @property
    def partitions(self) -> Union[List[Mountable], None]:
        if self.__partitions:
            return self.__partitions

        self.__partitions = []
        for start, size, type in self.__iter_partitions():
            if not type.startswith('Linux'):
                raise NotImplementedError('only Linux filesystem partitions are supported for now')
            self.__partitions.append(
                LinuxDiskImage(self.name, offset=start, lomode='udisksctl' if self.__in_qcow2 else 'mount')
            )

        return self.__partitions
