
import os
import shutil
import subprocess
import sys


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


def find_recursive_unix(root: str, name_patterns: list =None, ignored_dirs=None, type='any', depth=-1):
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
    return bout.decode('ascii').splitlines()


def check_ignored(path, ignored_dirs):
    path = os.path.normpath(path)
    for dir in ignored_dirs:
        if path == dir or path.startswith(dir + os.path.sep):
            return True
    return False


def find_recursive(root: str, name_patterns: list = None, ignored_dirs=None, type='any', depth=-1):
    if sys.platform == "darwin" or sys.platform.startswith('linux'):
        return find_recursive_unix(root, name_patterns=name_patterns, ignored_dirs=ignored_dirs, type=type, depth=depth)
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

