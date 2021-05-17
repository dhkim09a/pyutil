from enum import Enum

from .mountables.linux_disk_image import LinuxDiskImage
from .mountables.qemu_qcow2_image import QemuQcow2Image


class MountableFileType(Enum):
    LINUX_DISK_IMAGE = LinuxDiskImage
    QEMU_QCOW2_IMAGE = QemuQcow2Image
