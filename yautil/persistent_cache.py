import os
import pickle
import hashlib
from pathlib import Path
from typing import Union

DEFAULT_CACHE_DIR = os.path.join(Path.home(), '.cache')
BUF_SIZE = 65536  # lets read stuff in 64kb chunks!


class PersistentCache:
    class Key:
        key: any
        keytype: str

        __hexdigest_value: str

        def __init__(self, key, keytype: str):
            assert isinstance(keytype, str) and keytype in ['str', 'file']
            self.key = key
            self.keytype = keytype
            self.__hexdigest_value = self._hexdigest()

        @property
        def hexdigest(self) -> str:
            return self.__hexdigest_value

        def _hexdigest(self) -> str:
            raise NotImplementedError

        def __hash__(self):
            return hash(hash(self.key) ^ hash(self.keytype) ^ hash(self.hexdigest))

        def __eq__(self, other):
            return hash(self) == hash(other)

    class StrKey(Key):
        def __init__(self, key):
            assert isinstance(key, str)
            super().__init__(key, 'str')

        def _hexdigest(self) -> str:
            return hex(hash(self.key))

    class FileKey(Key):
        def __init__(self, key):
            assert isinstance(key, str)
            if not os.path.isfile(key):
                raise FileNotFoundError(key)

            super().__init__(os.path.realpath(key), 'file')

        def _hexdigest(self) -> str:
            sha1 = hashlib.sha1()

            with open(self.key, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha1.update(data)
            return sha1.hexdigest()

    class _Entry:
        key: any
        value: any

        def __init__(self, key, value):
            self.key = key
            self.value = value

    cache_dir: str
    keys: set

    def __locate_value(self, key: Key) -> str:
        return os.path.join(self.cache_dir, '__cache_entry_' + key.hexdigest)

    def __init__(self, cache_dir=DEFAULT_CACHE_DIR):
        self.cache_dir = cache_dir
        self.keys = set()

        if not os.path.isdir(cache_dir):
            raise NotADirectoryError(cache_dir)

        for file in os.listdir(self.cache_dir):
            path = os.path.join(self.cache_dir, file)
            if not os.path.isfile(path):
                continue

            try:
                with open(path, 'rb') as f:
                    e: PersistentCache._Entry = pickle.load(f)
                assert isinstance(e, PersistentCache._Entry)
            except Exception as e:
                print(e)
                continue

            self.keys.add(e.key)

    def lookup(self, key: Key) -> any:
        if key not in self:
            raise KeyError(key)

        value_path = self.__locate_value(key)
        with open(value_path, 'rb') as f:
            e: PersistentCache._Entry = pickle.load(f)
        return e.value

    def update(self, key: Key, value):
        value_path = self.__locate_value(key)
        with open(value_path, 'wb') as f:
            pickle.dump(PersistentCache._Entry(key, value), f)

        matches = [*filter(lambda e: e == key, self.keys)]
        if matches:
            assert len(matches) == 1
            self.remove(matches[0])
        self.keys.add(key)

    def remove(self, key: Key):
        value_path = self.__locate_value(key)
        if os.path.isfile(value_path):
            os.remove(value_path)
        self.keys.remove(key)

    def __contains__(self, item):
        return item in self.keys
