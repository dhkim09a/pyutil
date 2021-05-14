import re
from typing import Union, List

import sh

from . import Mountable, LinuxDiskImage


class DiskImage(Mountable):
    __partitions: List[Mountable] = None

    def __iter_partitions(self):
        rc = sh.fdisk(self.name, l=True, o='Start,End,Sectors', color='never', _iter=True)
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
                start, end, sectors = (*map(int, line.split()),)
            except ValueError:
                # skip column titles
                continue

            assert end - start + 1 == sectors
            # print(f'start: {start}, sector_size: {sector_size}')

            yield start * sector_size, sectors * sector_size

    def _mount(self, file: str, mode: str, mount_point: str):
        assert False

    def _umount(self, mount_point):
        assert False

    @classmethod
    def _pattern(cls) -> str:
        return r'boot sector'

    @property
    def partitions(self) -> Union[list, None]:
        if self.__partitions:
            return self.__partitions

        self.__partitions = []
        for start, size in self.__iter_partitions():
            self.__partitions.append(LinuxDiskImage(self.name, offset=start, lomode='udisksctl'))

        return self.__partitions
