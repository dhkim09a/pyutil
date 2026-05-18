import os
import stat
from os import path as _p
from tempfile import TemporaryDirectory
from unittest import TestCase

from yautil.file import (
    Writable,
    find,
    find_recursive,
    get_memtmpdir,
    remove_contents,
)


class TestRemoveContents(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_removes_files(self):
        with open(_p.join(self.root, 'a.txt'), 'w') as f:
            f.write('hi')
        with open(_p.join(self.root, 'b.txt'), 'w') as f:
            f.write('hi')
        remove_contents(self.root)
        self.assertEqual(os.listdir(self.root), [])

    def test_removes_subdirs(self):
        os.makedirs(_p.join(self.root, 'sub'))
        with open(_p.join(self.root, 'sub', 'x'), 'w') as f:
            f.write('hi')
        remove_contents(self.root)
        self.assertEqual(os.listdir(self.root), [])

    def test_empty_dir_passes(self):
        remove_contents(self.root)
        self.assertEqual(os.listdir(self.root), [])


class TestWritable(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.path = _p.join(self.tmp.name, 'ro.txt')
        with open(self.path, 'w') as f:
            f.write('hi')
        # Remove write bit
        os.chmod(self.path, 0o400)

    def tearDown(self):
        os.chmod(self.path, 0o600)
        self.tmp.cleanup()

    def test_makes_file_writable_in_context(self):
        with Writable(self.path):
            mode = os.stat(self.path).st_mode
            self.assertTrue(mode & stat.S_IWUSR)

    def test_restores_mode_on_exit(self):
        original = os.stat(self.path).st_mode
        with Writable(self.path):
            os.chmod(self.path, 0o600)  # alter inside
        # exiting restores recorded mode
        self.assertEqual(os.stat(self.path).st_mode, original)

    def test_nonexistent_file_ignored(self):
        # Filtered out at construction since it isn't a file
        ctx = Writable('/nonexistent/path/abc')
        with ctx:
            pass  # should not raise


class TestFind(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = self.tmp.name
        # build a small tree
        os.makedirs(_p.join(self.root, 'sub'))
        open(_p.join(self.root, 'a.txt'), 'w').close()
        open(_p.join(self.root, 'b.log'), 'w').close()
        open(_p.join(self.root, 'sub', 'c.txt'), 'w').close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_find_all(self):
        results = find(self.root)
        self.assertIsInstance(results, list)
        paths = list(results)
        self.assertTrue(any('a.txt' in p for p in paths))
        self.assertTrue(any('c.txt' in p for p in paths))

    def test_find_by_name(self):
        results = list(find(self.root, name='*.txt'))
        self.assertTrue(all(p.endswith('.txt') for p in results))
        self.assertTrue(any('a.txt' in p for p in results))
        self.assertTrue(any('c.txt' in p for p in results))
        self.assertFalse(any('b.log' in p for p in results))

    def test_find_files_only(self):
        results = list(find(self.root, type='f'))
        for p in results:
            self.assertTrue(_p.isfile(p))

    def test_find_recursive_files(self):
        results = find_recursive(self.root, type='file', sort=True)
        self.assertTrue(any('a.txt' in p for p in results))
        self.assertTrue(any('c.txt' in p for p in results))


class TestGetMemtmpdir(TestCase):
    def test_returns_none_or_tempdir_based_on_shm(self):
        result = get_memtmpdir()
        # On macOS, /dev/shm doesn't exist; should be None.
        if not _p.isdir('/dev/shm'):
            self.assertIsNone(result)
        else:
            self.assertIsNotNone(result)
            result.cleanup()

    def test_explicit_dir_works(self):
        with TemporaryDirectory() as outer:
            tmp = get_memtmpdir(dir=outer)
            self.assertIsNotNone(tmp)
            self.assertTrue(tmp.name.startswith(outer))
            tmp.cleanup()
