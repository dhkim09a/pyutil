
import os
import shutil
import subprocess
import sys
import tempfile
from os import path as _p
from typing import Iterable, Union, Optional, Literal

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


def find_recursive_unix(root: str, name_patterns: Optional[list] = None, ignored_dirs=None, type='any', depth=-1, sort=False):
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
           name: Union[str, list[str], None] = None,
           type: Optional[str] = None,
           depth: Optional[int] = None,
           exclude_dir: Union[str, list[str], None] = None,
           printf: Union[str, Literal[False]] = False,
           iter: bool = False,
        #    iter_nonblock: bool = False,
           follow_symlinks: str = 'never',
           bufsize: int = 0,
           ) -> Iterable[str]:

    find_opts = []
    find_target_opts = []

    if follow_symlinks == 'never':
        find_opts.append('-P')
    elif follow_symlinks == 'yes':
        find_opts.append('-L')
    elif follow_symlinks == 'no':
        find_opts.append('-H')
    else:
        raise ValueError(f"find()'s follow_symlinks must be one of 'never', 'yes', or 'no' (default: 'never'), but {follow_symlinks} is given.")

    find_opts += [root]

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

    if printf:
        find_opts.extend(['-printf', printf])

    # print(find_opts)

    # if not (iter_nonblock or iter) and (rd := get_memtmpdir()):
    if not iter and (rd := get_memtmpdir()):
        # print(f'rd: {rd}')
        find_outs = _p.join(rd.name, 'f')
        sh.find(*find_opts, _out=find_outs) # type: ignore

        with open(find_outs, 'r') as f:
            # while line := f.readline():
            while True:
                line = f.readline()
                if not line:
                    break
                yield line.strip()
    elif bufsize > 1:
        remainings: str = ''
        # for path in sh.find(*find_opts, _iter_noblock=iter_nonblock, _iter=iter, _out_bufsize=bufsize): # type: ignore
        for path in sh.find(*find_opts, _iter=iter, _out_bufsize=bufsize): # type: ignore
            if not path:
                continue
            lines = str(path).split('\n')
            for line in lines[:-1]:
                if remainings:
                    # print(remainings + line)
                    yield(remainings + line)
                    remainings = ''
                else:
                    # print(line)
                    yield(line)
            if lines[-1]:
                remainings += lines[-1]
        if remainings:
            # print(remainings)
            yield(remainings)
    else:
        # for path in sh.find(*find_opts, _iter_noblock=iter_nonblock, _iter=iter): # type: ignore
        for path in sh.find(*find_opts, _iter=iter): # type: ignore
            if not path:
                continue
            yield str(path).strip()


def find(root: str,
         name: Union[str, list[str], None] = None,
         type: Optional[str] = None,
         depth: Optional[int] = None,
         exclude_dir: Union[str, list[str], None] = None,
         printf: Union[str, Literal[False]] = False,
         iter: bool = False,
        #  iter_nonblock: bool = False,
         follow_symlinks: str = 'never',
         bufsize: int = 0,
         ) -> Iterable[str]:
    ret = __find(
        root=root,
        name=name,
        type=type,
        depth=depth,
        exclude_dir=exclude_dir,
        printf=printf,
        iter=iter,
        # iter_nonblock=iter_nonblock,
        follow_symlinks=follow_symlinks,
        bufsize=bufsize,
    )
    # if iter or iter_nonblock:
    if iter:
        return ret
    else:
        return [*ret]


def find_recursive(root: str,
                   name_patterns: Optional[list[str]] = None,
                   ignored_dirs: Union[str, list[str], None] = None,
                   type: Literal['any', 'dir', 'file'] = 'any',
                   depth=-1,
                   sort=False,
                   ) -> list[str]:
    if sys.platform == "darwin" or sys.platform.startswith('linux'):
        # return find_recursive_unix(root, name_patterns=name_patterns, ignored_dirs=ignored_dirs, type=type, depth=depth, sort=sort)
        paths: list[str] = list(find(root,
                     name=name_patterns,
                     type='d' if type == 'dir' else 'f' if type == 'file' else None,
                     depth=depth if depth >= 0 else None,
                     exclude_dir=ignored_dirs))
        if sort:
            paths.sort()
        return paths
    else:
        paths: list[str] = []
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


@static_vars(mkdir=sh.mkdir.bake(p=True), # type: ignore
             rsync=sh.rsync.bake(a=True, partial=True, delete=True)) # type: ignore
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

