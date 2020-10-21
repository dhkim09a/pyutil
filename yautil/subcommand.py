# PYTHON_ARGCOMPLETE_OK

import argparse
from typing import Union, List

try:
    import argcomplete
except ImportError:
    pass


class Subcommand:
    parser: argparse.ArgumentParser
    name: str

    def on_parser_init(self, parser: argparse.ArgumentParser):
        raise NotImplementedError

    def on_command(self, args):
        raise NotImplementedError

    def _register(self, subparsers, _help=None):
        self.parser = subparsers.add_parser(self.name, help=_help)
        self.parser.set_defaults(func=self.on_command)
        self.on_parser_init(self.parser)
        if subparsers.metavar:
            subparsers.metavar = subparsers.metavar + ', ' + self.name
        else:
            subparsers.metavar = self.name

    def __init__(self, subparsers = None, name: str = None, help: str = '', dependency: Union[str, List[str]] = ''):
        self.name = name if name else type(self).__name__.lower()
        if subparsers:
            self._register(subparsers, _help=help)


class SubcommandParser(argparse.ArgumentParser):
    subparsers = None
    args = None

    argcomplete: bool

    def __init__(self, *args, argcomplete: bool = False, **kwargs):
        super().__init__(*args, **kwargs)

        self.argcomplete = argcomplete

    def add_subcommands(self, *subcommands: Subcommand):
        if not self.subparsers:
            self.subparsers = self.add_subparsers()
            self.subparsers.required = True
            self.subparsers.dest = 'subcommand'

        for subcommand in subcommands:
            if isinstance(subcommand, Subcommand):
                subcommand._register(self.subparsers)

    def parse_args(self, *args, **kwargs) -> object:
        if self.argcomplete:
            if 'argcomplete' in globals():
                argcomplete.autocomplete(self)
            else:
                print('warning: install \'argcomplete\' package to enable bash autocomplete')
        self.args = super().parse_args(*args, **kwargs)
        return self.args

    def exec_subcommands(self, parsed_args: object = None):
        if not parsed_args:
            parsed_args = self.args
        if not parsed_args:
            parsed_args = self.parse_args()

        parsed_args.func(parsed_args)