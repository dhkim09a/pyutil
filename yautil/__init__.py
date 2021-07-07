
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

from .mputil import MpUtil, globalize
from .subcommand import Subcommand, SubcommandParser
from .fileutil import remove_contents, find_recursive, overwrite, get_memtmpdir, find
from .decorators import static_vars
from .eventutil import EventGenerator, Event
from .strutil import decomment_cxx, strcompare
from .plotutil import plot_cdf, plot_linear, plot_scatter, plot_box, plot_stack
from .cacheutil import PersistentCache
from .dockerutil import docker_sh
from .gitutil import git_expand
from .pyshutil import compile_shargs

builtins.__import__ = realimport
