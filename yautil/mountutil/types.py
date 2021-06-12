from enum import Enum

from .core import Mountable, Archive
from .mountables import LinuxDiskImage, QemuQcow2Image, Yaffs2Archive, CpioArchive, Qcow2Image


class MountableType(Enum):
    AUTO = Mountable
    LINUX_DISK_IMAGE = LinuxDiskImage
    QEMU_QCOW2_IMAGE = QemuQcow2Image
    QCOW2_IMAGE = Qcow2Image
    CPIO_ARCHIVE = CpioArchive
    YAFFS2_ARCHIVE = Yaffs2Archive

    def instantiate(self, file: str, **type_specific_args) -> Mountable:
        return self.value(file, **type_specific_args)


class ArchiveType(Enum):
    AUTO = Archive
    CPIO_ARCHIVE = CpioArchive
    YAFFS2_ARCHIVE = Yaffs2Archive

    def instantiate(self, file: str) -> Archive:
        return self.value(file)
