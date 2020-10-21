import argparse
from typing import Union, List

# PYTHON_ARGCOMPLETE_OK

class Subcommand:
    parser: argparse.ArgumentParser
    name: str

    def on_parser_init(self, parser: argparse.ArgumentParser):
        raise NotImplementedError

    def on_command(self, args):
        raise NotImplementedError

    # def ensure_package(self, name: str) -> bool:
    #     if name in globals():
    #         return True
    #     print('Python package \'' + name + '\' is required but not found')
    #     return False

    def _register(self, subparsers):
        self.parser = subparsers.add_parser(self.name, help=help)
        self.parser.set_defaults(func=self.on_command)
        self.on_parser_init(self.parser)
        if subparsers.metavar:
            subparsers.metavar = subparsers.metavar + ', ' + self.name
        else:
            subparsers.metavar = self.name

    def __init__(self, subparsers = None, name: str = None, help='', dependency: Union[str, List[str]] = ''):
        self.name = name if name else type(self).__name__.lower()
        if subparsers:
            self._register(subparsers)

        # if dependency:
        #     if type(dependency) is str:
        #         if self.ensure_package(dependency) is False:
        #             quit(-1)
        #     elif type(dependency) is list:
        #         for name in dependency:
        #             if self.ensure_package(name) is False:
        #                 quit(-1)
        #     else:
        #         print("Internal error")


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
            try:
                import argcomplete
                argcomplete.autocomplete(super())
            except ImportError:
                print('error: install \'argcomplete\' package to enable bash autocomplete')
        self.args = super().parse_args(*args, **kwargs)
        return self.args

    def exec_subcommands(self, parsed_args: object = None):
        if not parsed_args:
            parsed_args = self.args
        if not parsed_args:
            parsed_args = self.parse_args()

        parsed_args.func(parsed_args)