import gzip
import os
import shutil
from os import path as _p
from tempfile import TemporaryDirectory
from typing import List
from unittest import TestCase, SkipTest

from ..mountutil import mount, extract, archive, MountableType, ArchiveType, DiskImage


class TestMountable(TestCase):
    test_dir: TemporaryDirectory
    test_vectors: List[str]

    @classmethod
    def setUpClass(cls):
        if cls is TestMountable:
            raise SkipTest("Skip BaseTest tests, it's a base class")
        super(TestMountable, cls).setUpClass()

    def setUp(self):
        self.test_dir = TemporaryDirectory()
        mountables_dir = _p.join(_p.dirname(__file__), 'mountables')
        for test_vector in self.test_vectors:
            if test_vector in os.listdir(mountables_dir):
                shutil.copyfile(_p.join(mountables_dir, test_vector), _p.join(self.test_dir.name, test_vector))
            elif test_vector + r'.gz' in os.listdir(mountables_dir):
                with gzip.open(_p.join(mountables_dir, test_vector + r'.gz'), 'rb') as f_in, \
                        open(_p.join(self.test_dir.name, test_vector), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        # print(sh.ls(self.test_dir.name))

    def usage_with(self, file: str, type: MountableType = MountableType.AUTO, gt: str = 'hello'):
        with mount(file, type=type) as m:
            with open(_p.join(m.name, 'hello'), 'r') as f:
                assert f.read().strip() == gt

    def usage_no_with(self, file: str, type: MountableType = MountableType.AUTO, gt: str = 'hello'):
        m = mount(file, type=type)

        with open(_p.join(m.name, 'hello'), 'r') as f:
            assert f.read().strip() == gt

        m.umount()


class TestArchive(TestMountable):
    test_dir: TemporaryDirectory
    test_vectors: List[str]

    @classmethod
    def setUpClass(cls):
        if cls is TestArchive:
            raise SkipTest("Skip BaseTest tests, it's a base class")
        super(TestArchive, cls).setUpClass()

    def usage_extract(self, file: str, type: ArchiveType = ArchiveType.AUTO, gt: str = 'hello'):
        tmpdir = TemporaryDirectory()
        extract(file, tmpdir.name, type=type)

        with open(_p.join(tmpdir.name, 'hello'), 'r') as f:
            assert f.read().strip() == gt


class TestLinuxDiskImage(TestMountable):
    def __init__(self, *args, **kwargs):
        self.test_vectors = ['ext4.img']
        super().__init__(*args, **kwargs)

    def test_with(self):
        self.usage_with(_p.join(self.test_dir.name, 'ext4.img'), type=MountableType.LINUX_DISK_IMAGE)

    def test_no_with(self):
        self.usage_no_with(_p.join(self.test_dir.name, 'ext4.img'), type=MountableType.LINUX_DISK_IMAGE)

    def test_implicit_type(self):
        self.usage_with(_p.join(self.test_dir.name, 'ext4.img'))


class TestYaffs2Oob(TestArchive):
    def __init__(self, *args, **kwargs):
        self.test_vectors = ['yaffs2_OOB.img']
        super().__init__(*args, **kwargs)

    def test_with(self):
        self.usage_with(_p.join(self.test_dir.name, 'yaffs2_OOB.img'), type=MountableType.YAFFS2_ARCHIVE)

    def test_no_with(self):
        self.usage_no_with(_p.join(self.test_dir.name, 'yaffs2_OOB.img'), type=MountableType.YAFFS2_ARCHIVE)

    # def test_implicit_type(self):
    #     self.usage_with(_p.join(self.test_dir.name, 'yaffs2_OOB.img'))

    def test_extract(self):
        self.usage_extract(_p.join(self.test_dir.name, 'yaffs2_OOB.img'), type=ArchiveType.YAFFS2_ARCHIVE)


class TestDiskImage(TestMountable):
    def __init__(self, *args, **kwargs):
        self.test_vectors = ['disk.img']
        super().__init__(*args, **kwargs)

    def test_with(self):
        file = _p.join(self.test_dir.name, 'disk.img')

        img = DiskImage(file)

        for i, partition in enumerate(img.partitions):
            with mount(partition) as m:
                with open(_p.join(m.name, 'hello'), 'r') as f:
                    assert f.read().strip() == 'hello' + str(i + 1)

    # def test_no_with(self):
    #     self.usage_no_with(_p.join(self.test_dir.name, 'ext4.img'), type=MountableType.LINUX_DISK_IMAGE)
    #
    # def test_implicit_type(self):
    #     self.usage_with(_p.join(self.test_dir.name, 'ext4.img'))
