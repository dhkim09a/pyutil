import os
from os import path as _p
from shutil import copyfile
import sh


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
