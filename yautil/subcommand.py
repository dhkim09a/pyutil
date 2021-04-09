# PYTHON_ARGCOMPLETE_OK

import argparse
from typing import Union, List
from gettext import gettext as _

from . import DummyModule
from .pyshutil import compile_shargs

try:
    import argcomplete
except ImportError:
    pass


class SubcommandParser(argparse.ArgumentParser):
    subparsers = None
    shared_parser = None

    argcomplete: bool
    __allow_unknown_args: bool

    __unknown_args: list = None

    @property
    def allow_unknown_args(self) -> bool:
        return self.__allow_unknown_args

    @allow_unknown_args.setter
    def allow_unknown_args(self, val: bool):
        self.__allow_unknown_args = val

    def __init__(self, *args, argcomplete: bool = False, **kwargs):
        super().__init__(*args, **kwargs)

        self.argcomplete = argcomplete
        self.allow_unknown_args = False

    def add_subcommands(self, *subcommands, title='subcommands', required=True, help=None, metavar=None):
        if not self.subparsers:
            self.subparsers = self.add_subparsers(
                title=title,
                required=required,
                help=help,
                metavar=metavar,
            )
            self.subparsers.dest = 'subcommand'

        for subcommand in subcommands:
            if not isinstance(subcommand, Subcommand):
                raise TypeError(str(subcommand.__class__) + 'is not Subcommand')
            subcommand._register(self.subparsers,
                                 parent=self.shared_parser)

    def try_argcomplete(self):
        if 'argcomplete' in globals() and not isinstance(argcomplete, DummyModule):
            argcomplete.autocomplete(self)
        else:
            print('warning: install \'argcomplete\' package to enable bash autocomplete')

    def parse_args(self, *args, **kwargs) -> any:
        if self.argcomplete:
            self.try_argcomplete()
        parsed_args, unknown_args = super().parse_known_args(*args, **kwargs)
        if unknown_args and not parsed_args._allow_unknown_args:
            msg = _('unrecognized arguments: %s')
            self.error(msg % ' '.join(unknown_args))
        self.__unknown_args = unknown_args
        return parsed_args

    def exec_subcommands(self, parsed_args: object = None):
        if not parsed_args:
            parsed_args = self.parse_args()

        if parsed_args._allow_unknown_args:
            parsed_args._func(parsed_args, unknown_args=self.__unknown_args)
        else:
            parsed_args._func(parsed_args)

    def add_argument(self, *args, shared: bool = False, **kwargs):
        if shared:
            if not self.shared_parser:
                self.shared_parser = argparse.ArgumentParser(add_help=False)

            return self.shared_parser.add_argument(*args, **kwargs)

        return super().add_argument(*args, **kwargs)


class Subcommand:
    parser: SubcommandParser
    name: str
    help: str

    def on_parser_init(self, parser: SubcommandParser):
        raise NotImplementedError

    def on_command(self, args, unknown_args=None):
        raise NotImplementedError

    def _register(self, subparsers, parent: argparse.ArgumentParser = None):
        kwargs = {'help': self.help}
        if parent:
            kwargs['parents'] = [parent]

        self.parser = subparsers.add_parser(self.name, **kwargs)
        self.parser.__class__ = SubcommandParser
        self.on_parser_init(self.parser)
        self.parser.set_defaults(
            _func=self.on_command,
            _allow_unknown_args=self.parser.allow_unknown_args,
        )
        subparsers.metavar = 'command'

    def __init__(self, subparsers = None, name: str = None, help: str = '', dependency: Union[str, List[str]] = ''):
        self.name = name if name else type(self).__name__.lower()
        self.help = help
        if subparsers:
            self._register(subparsers)

    @classmethod
    def exec(cls, *args, **kwargs):
        cmdargs, shargs = compile_shargs(*args, **kwargs)

        parser = SubcommandParser()
        parser.add_subcommands(cls(name='subcmd'))
        parserd_args = parser.parse_args(['subcmd', *cmdargs])

        parser.exec_subcommands(parserd_args)
