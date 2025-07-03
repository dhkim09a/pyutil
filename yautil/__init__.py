
# Ignore import errors
# https://stackoverflow.com/a/6077117/3836385

import builtins
from types import ModuleType

# argcomplete does not work when import errors are ignored.
try:
    import argcomplete
except ImportError:
    pass


class DummyModule(ModuleType):
    def __getattr__(self, key):
        return None

    __all__ = []  # support wildcard imports


def tryimport(name, globals={}, locals={}, fromlist=[], level=-1):
    try:
        return realimport(name, globals, locals, fromlist, level)
    except ImportError:
        return DummyModule(name)


realimport, builtins.__import__ = builtins.__import__, tryimport

from .argparse import WarningAction, SplitAppendAction
from .file import remove_contents, find_recursive, overwrite, get_memtmpdir, find
from .decorators import static_vars
from .event import EventGenerator, Event
from .print import decomment_cxx, strcompare, auto_print
from .plot import plot_cdf, plot_linear, plot_scatter, plot_box, plot_stack
from .lru_cache_ext import lru_cache
from .persistent_cache import PersistentCache
from .docker_sh import docker_sh, AuthorizationError
from .git import git_expand
from .io import FilteredTextIO
from .pysh import compile_shargs, get_cmd_args

builtins.__import__ = realimport
