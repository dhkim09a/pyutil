import re

import sh

from ..core import Mountable
from .linux_disk_image import LinuxDiskImage


class DiskImage(Mountable):
    __partitions: list[Mountable | None] | None = None
    __in_qcow2: bool = False

    def __init__(self, file: str, in_qcow2: bool = False):
        super().__init__(file)
        self.__in_qcow2 = in_qcow2

    def __iter_partitions(self) -> list[tuple[int, int, str]]:
        rc = str(sh.fdisk(self.name, l=True, o='Start,End,Sectors,Type', color='never', _iter=True)) # type: ignore
        sector_size = 512

        for line in rc:
            line = str(line).strip()

            if m := re.search(r'Units:.*?(?P<sector_size>\d+) bytes', line):
                sector_size = int(m['sector_size'])

            if not line:
                break

        result = []
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

            result.append((start * sector_size, sectors * sector_size, type.strip()))

        return result

    def _mount(self, file: str, mode: str, mount_point: str) -> None:
        assert False

    def _umount(self, mount_point: str) -> None:
        assert False

    @classmethod
    def _ismountable(cls, path: str | None = None, file_cmd_out: str | None = None) -> bool:
        if file_cmd_out is None:
            return False
        return r'boot sector' in file_cmd_out

    @property
    def partitions(self) -> list[Mountable | None] | None:
        if self.__partitions is not None:
            return self.__partitions

        self.__partitions = []
        for start, size, type in self.__iter_partitions():
            if type in ['Linux filesystem', 'W95 FAT32']:
                partition = LinuxDiskImage(self.name, offset=start, lomode='udisksctl' if self.__in_qcow2 else 'mount')
            else:
                partition = None
                # raise NotImplementedError('only Linux filesystem partitions are supported for now')
            self.__partitions.append(partition)

        return self.__partitions
