import os
from os import path as _p
from shutil import copyfile
import sys
from typing import Literal
import sh

from .file import Writable


def link_repo(base: str, target: str):
    if not _p.isdir(base):
        raise NotADirectoryError(base)

    if not _p.isdir(target):
        raise NotADirectoryError(target)

    base_repo = _p.realpath(_p.join(base, '.git'))

    if not _p.isdir(base_repo):
        raise NotADirectoryError(base_repo)

    target_repo = _p.realpath(_p.join(target, '.git'))

    if _p.exists(target_repo):
        raise FileExistsError(target_repo)

    os.mkdir(target_repo)

    items_to_copy = {'HEAD', 'ORIG_HEAD'}
    items_to_omit = {'index'}
    items_to_step_in = {'logs'}
    items_to_ignore = []

    for root, dirs, files in os.walk(base_repo):
        root_path = _p.relpath(root, base_repo)
        skip = [*filter(lambda s: root_path == s or root_path.startswith(s + _p.sep), items_to_ignore)]
        if skip:
            continue

        for item in dirs + files:
            item_path = _p.relpath(_p.join(root, item), base_repo)
            if item in items_to_copy:
                assert _p.isfile(_p.join(base_repo, item_path))
                copyfile(_p.join(base_repo, item_path), _p.join(target_repo, item_path))
            elif item in items_to_omit:
                pass
            elif item in items_to_step_in:
                assert _p.isdir(_p.join(base_repo, item_path))
                os.mkdir(_p.join(target_repo, item_path))
            else:
                os.symlink(_p.join(base_repo, item_path), _p.join(target_repo, item_path))
                items_to_ignore.append(item_path)


def __git_expand(repo: str, dest: str, *checkout_targets: str, ignore_errors=False):
    if not _p.isdir(repo):
        raise NotADirectoryError(repo)

    if not _p.isdir(dest):
        raise NotADirectoryError(dest)

    dest_items = os.listdir(dest)

    if dest_items:
        for checkout_target in checkout_targets:
            if checkout_target in dest_items:
                raise FileExistsError(_p.join(dest, checkout_target))

    for checkout_target in checkout_targets:
        target_repo = _p.realpath(_p.join(dest, checkout_target))
        try:
            os.makedirs(target_repo, exist_ok=True)
            link_repo(repo, target_repo)
            sh.git.checkout(checkout_target, _cwd=target_repo)
        except:
            if ignore_errors:
                yield None
            else:
                raise Exception(f'Failed to checkout {checkout_target}')

        yield target_repo


def git_expand(repo: str, dest: str, *checkout_targets: str, ignore_errors=False, iter=False):
    if iter:
        return __git_expand(repo, dest, *checkout_targets, ignore_errors=ignore_errors)
    else:
        return [*__git_expand(repo, dest, *checkout_targets, ignore_errors=ignore_errors)]


def git_merge_file(
    file1: str, base: str, file2: str,
    labels: tuple[str, str, str] | None = None,
    binary: Literal['file1', 'file2'] | None = None,
) -> bool:
    try:
        patched: str | bytes = str(sh.Command('git').bake(
            'merge-file',
            *(['-L', labels[0], '-L', labels[1], '-L', labels[2]] if labels else []),
            stdout = True,
            # ours = conflict == 'file1',
            # theirs = conflict == 'file2',
            # _err=sys.stderr,
            _ok_code=range(128),
        )(file1, base, file2))
    except sh.ErrorReturnCode as e:
        if e.exit_code > 128:
            is_binary = 'Cannot merge binary files' in e.stderr.decode('utf-8')
            if is_binary and binary == 'file1':
                # FIXME: This overwrites file1 with file1 which is unnecessary
                with open(file1, 'rb') as f:
                    patched = f.read()
            elif is_binary and binary == 'file2':
                with open(file2, 'rb') as f:
                    patched = f.read()
            else:
                print(f'{e.stderr.decode("utf-8").strip()} (file1={file1}, base={base}, file2={file2})', file=sys.stderr)
                return False
        # else:
        #     print(f'info: {e.exit_code} conflicts resoved automatically.', file=sys.stderr)

    with Writable(file1):
        if isinstance(patched, str):
            with open(file1, 'w') as f:
                f.write(patched)
        elif isinstance(patched, bytes):
            with open(file1, 'wb') as f:
                f.write(patched)
        else:
            print(f'internal error: unknown type of patched: {type(patched)}', file=sys.stderr)

    return True


