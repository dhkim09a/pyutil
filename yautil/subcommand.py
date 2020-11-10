# PYTHON_ARGCOMPLETE_OK

import argparse
from typing import Union, List, Text, Type, Any, Callable, Iterable, Optional, Tuple

try:
    import argcomplete
except ImportError:
    pass


class SubcommandParser(argparse.ArgumentParser):
    subparsers = None
    shared_parser = None

    argcomplete: bool

    def __init__(self, *args, argcomplete: bool = False, **kwargs):
        super().__init__(*args, **kwargs)

        self.argcomplete = argcomplete

    def add_subcommands(self, *subcommands):
        if not self.subparsers:
            self.subparsers = self.add_subparsers()
            self.subparsers.required = True
            self.subparsers.dest = 'subcommand'

        for subcommand in subcommands:
            if not isinstance(subcommand, Subcommand):
                raise TypeError(str(subcommand.__class__) + 'is not Subcommand')
            subcommand._register(self.subparsers,
                                 parent=self.shared_parser)

    def parse_args(self, *args, **kwargs) -> any:
        if self.argcomplete:
            if 'argcomplete' in globals():
                argcomplete.autocomplete(self)
            else:
                print('warning: install \'argcomplete\' package to enable bash autocomplete')
        return super().parse_args(*args, **kwargs)

    def exec_subcommands(self, parsed_args: object = None):
        if not parsed_args:
            parsed_args = self.parse_args()

        parsed_args.func(parsed_args)

    def add_argument(self, *args, shared: bool = False, **kwargs):
        if shared:
            if not self.shared_parser:
                self.shared_parser = argparse.ArgumentParser(add_help=False)

            return self.shared_parser.add_argument(*args, **kwargs)

        return super().add_argument(*args, **kwargs)


class Subcommand:
    parser: argparse.ArgumentParser
    name: str

    def on_parser_init(self, parser: SubcommandParser):
        raise NotImplementedError

    def on_command(self, args):
        raise NotImplementedError

    def _register(self, subparsers, _help=None, parent: argparse.ArgumentParser = None):
        kwargs = {'help': _help}
        if parent:
            kwargs['parents'] = [parent]

        self.parser = subparsers.add_parser(self.name, **kwargs)
        self.parser.__class__ = SubcommandParser
        self.parser.set_defaults(func=self.on_command)
        self.on_parser_init(self.parser)
        subparsers.metavar = 'command'

    def __init__(self, subparsers = None, name: str = None, help: str = '', dependency: Union[str, List[str]] = ''):
        self.name = name if name else type(self).__name__.lower()
        if subparsers:
            self._register(subparsers, _help=help)
