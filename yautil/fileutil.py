
import os
import shutil
import subprocess
import sys
import tempfile
from os import path as _p
from typing import Union, List

import sh

from .decorators import static_vars


def remove_contents(folder: str):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


def find_recursive_unix(root: str, name_patterns: list =None, ignored_dirs=None, type='any', depth=-1, sort=False):
    # find . -type d \( -path dir1 -o -path dir2 -o -path dir3 \) -prune -o -print
    find_cmd = 'find ' + root + ' '
    find_filter = ''

    if depth >= 0:
        find_cmd += '-maxdepth ' + str(depth) + ' '

    if name_patterns:
        find_filter += r'\( '
        find_filter += '-o '.join('-name \'' + e + '\' ' for e in name_patterns)
        find_filter += r'\) '

    if type == 'dir':
        find_filter += '-type d '
    elif type == 'file':
        find_filter += '-type f '
    elif type == 'any':
        pass
    else:
        return

    if ignored_dirs:
        find_cmd += r'-type d \( '
        while ignored_dirs:
            find_cmd += '-path ' + os.path.join(root, ignored_dirs.pop()) + ' '
            if ignored_dirs:
                find_cmd += '-o '
        find_cmd += r'\) -prune -o ' + find_filter + '-print'
    else:
        find_cmd += find_filter
    bout = subprocess.check_output(find_cmd, shell=True)
    out = bout.decode('utf-8').splitlines()
    if sort:
        out.sort()
    return out


def check_ignored(path, ignored_dirs):
    path = os.path.normpath(path)
    for dir in ignored_dirs:
        if path == dir or path.startswith(dir + os.path.sep):
            return True
    return False


def __find(root: str,
           name: Union[str, List[str]] = None,
           type: str = None,
           depth: int = None,
           exclude_dir: Union[str, List[str]] = None,
           iter_nonblock: bool = False
           ) -> any:

    find_opts = [root]
    find_target_opts = []

    if depth is not None:
        find_opts.extend(['-maxdepth', depth])

    if name:
        if not isinstance(name, list):
            name = [name]

        find_target_opts += '('
        while name:
            find_target_opts.extend(['-name', name.pop()])
            if name:
                find_target_opts.append('-o')
        find_target_opts += ')'

    if type:
        find_target_opts.extend(['-type', type])

    if exclude_dir:
        if not isinstance(exclude_dir, list):
            exclude_dir = [exclude_dir]

        find_opts.extend(['-type', 'd', '('])
        while exclude_dir:
            find_opts.extend(['-path', _p.join(root, exclude_dir.pop())])
            if exclude_dir:
                find_opts.append('-o')
        find_opts.extend([')', '-prune', '-o', *find_target_opts, '-print'])
    else:
        find_opts.extend(find_target_opts)

    # print(find_opts)
    # if rd := get_memtmpdir():
    rd = get_memtmpdir()
    if rd:
        find_outs = _p.join(rd.name, 'f')
        sh.find(*find_opts, _out=find_outs)

        def get_paths():
            with open(find_outs, 'r') as f:
                # while line := f.readline():
                while True:
                    line = f.readline()
                    if not line:
                        break
                    yield line
    else:
        get_paths = sh.find.bake(*find_opts, _iter_noblock=iter_nonblock, _iter=True)

    for path in get_paths():
        if path:
            yield str(path).strip()


def find(root: str,
         name: str = None,
         type: str = None,
         depth: int = None,
         exclude_dir: Union[str, List[str]] = None,
         iter: bool = False,
         iter_nonblock: bool = False,
         ) -> any:
    ret = __find(root=root, name=name, type=type, depth=depth, exclude_dir=exclude_dir,
                 iter_nonblock=iter_nonblock)
    if iter or iter_nonblock:
        return ret
    else:
        return [*ret]


def find_recursive(root: str, name_patterns: list = None, ignored_dirs=None, type='any', depth=-1, sort=False):
    if sys.platform == "darwin" or sys.platform.startswith('linux'):
        # return find_recursive_unix(root, name_patterns=name_patterns, ignored_dirs=ignored_dirs, type=type, depth=depth, sort=sort)
        paths = find(root,
                     name=name_patterns,
                     type='d' if type == 'dir' else 'f' if type == 'file' else None,
                     depth=depth if depth >= 0 else None,
                     exclude_dir=ignored_dirs)
        return paths.sort() if sort else paths
    else:
        paths = []
        for root, dirs, fnames in os.walk(root):
            if ignored_dirs and check_ignored(root, ignored_dirs):
                continue
            if type == 'any' or type == 'dir':
                for dir in dirs:
                    if ignored_dirs and check_ignored(dir, ignored_dirs):
                        continue
                    paths.append(os.path.join(root, dir))
            if type == 'any' or type == 'file':
                for fname in fnames:
                    paths.append(os.path.join(root, fname))
        return paths


@static_vars(mkdir=sh.mkdir.bake(p=True),
             rsync=sh.rsync.bake(a=True, partial=True, delete=True))
def overwrite(src: str, dst: str):
    if os.path.isdir(src):
        src = src + os.path.sep

    if not os.path.exists(dst):
        overwrite.mkdir(os.path.dirname(dst))
    elif os.path.isdir(dst):
        dst = dst + os.path.sep

    overwrite.rsync(src, dst)


def get_memtmpdir(suffix=None, prefix=None, dir=None) -> Union[None, tempfile.TemporaryDirectory]:
    if dir:
        return tempfile.TemporaryDirectory(suffix=suffix, prefix=prefix, dir=dir)

    memdirs = ['/dev/shm']
    for dir in memdirs:
        if not os.path.isdir(dir):
            continue
        return tempfile.TemporaryDirectory(suffix=suffix, prefix=prefix, dir=dir)

    return None

