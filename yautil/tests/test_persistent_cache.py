import os
from unittest import TestCase

from yautil import PersistentCache
from tempfile import TemporaryDirectory


class TestCache(TestCase):
    tmpdir: TemporaryDirectory
    cache_dir: str
    files_dir: str

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.cache_dir = os.path.join(self.tmpdir.name, 'cache')
        os.mkdir(self.cache_dir)
        self.files_dir = os.path.join(self.tmpdir.name, 'files')
        os.mkdir(self.files_dir)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_rw(self):
        pc = PersistentCache(cache_dir=self.cache_dir)

        key = pc.StrKey('x')

        assert key not in pc

        pc.update(key, 'val_x')

        assert key in pc

        value = pc.lookup(pc.StrKey('x'))

        assert value == 'val_x'

    def test_rw_filekey(self):
        pc = PersistentCache(cache_dir=self.cache_dir)

        f1 = os.path.join(self.files_dir, 'f1')
        with open(f1, 'w') as f:
            f.write('hello')

        key = pc.FileKey(f1)

        assert key not in pc

        pc.update(key, 'val_1')

        assert key in pc

        with open(f1, 'w') as f:
            f.write('bye')

        key2 = pc.FileKey(f1)

        assert key2 not in pc

        assert pc.lookup(key) == 'val_1'

        pc.update(key2, 'val_2')

        assert key in pc
        assert key2 in pc

        pc.remove(key)

        assert key not in pc
        assert key2 in pc

        assert pc.lookup(key2) == 'val_2'
