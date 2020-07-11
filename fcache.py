import os
import hashlib
from typing import Union, List

import sh

from .fileutil import find_recursive
from .mputil import MpUtil


def hash_str(string: str) -> str:
    return hashlib.sha1(string.encode('utf-8')).hexdigest()


def hash_path(path: str) -> Union[str, None]:
    if not os.path.exists(path):
        return None

    files: List[str] = find_recursive(path, type='file')

    if not files:
        return None

#    return hash_str(sh.sha1sum(files))
    h = hashlib.sha1()
    for file in files:
        h.update(bytes(os.path.getmtime(file).hex().encode('ascii')))
    return h.hexdigest()


class FCache:
    cache_dir: str

    def __init__(self, cache_dir: str):
        self.cache_dir = os.path.realpath(cache_dir)

    def __get_cache(self, path: str) -> str:
        return os.path.join(self.cache_dir, hash_str(path))

    def update(self, src_path: str, value_path: str) -> bool:
        return False

        src_path = os.path.realpath(src_path)
        if not os.path.exists(src_path):
            return False

        value_path = os.path.realpath(value_path)
        if not os.path.exists(value_path):
            return False

        cache_path = self.__get_cache(src_path)

        if not os.path.isdir(cache_path):
            mkdir(cache_path)

        sign = hash_path(src_path)

        with open(os.path.join(cache_path, 'sign'), 'w+') as f:
            f.write(sign)

        overwrite(value_path, os.path.join(cache_path, 'value'))

        return True

    def get(self, src_path: str, dst_path: str) -> bool:
        return False

        src_path = os.path.realpath(src_path)
        if not os.path.exists(src_path):
            # print('miss: ' + src_path + ' to ' + dst_path)
            return False

        dst_path = os.path.realpath(dst_path)

        cache_path = self.__get_cache(src_path)

        if not os.path.isdir(cache_path):
            # print('miss: ' + src_path + ' to ' + dst_path)
            return False

        curr_sign = hash_path(src_path)

        with open(os.path.join(cache_path, 'sign'), 'r') as f:
            sign = f.read()

        if curr_sign != sign:
            # print('miss: ' + src_path + ' to ' + dst_path)
            return False

        overwrite(os.path.join(cache_path, 'value'), dst_path)

        return True
