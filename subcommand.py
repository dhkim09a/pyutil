import argparse
from typing import Union, List


class Subcommand:
    parser: argparse.ArgumentParser

    def on_parser_init(self, parser: argparse.ArgumentParser):
        raise NotImplementedError

    def on_command(self, args):
        raise NotImplementedError

    # def ensure_package(self, name: str) -> bool:
    #     if name in globals():
    #         return True
    #     print('Python package \'' + name + '\' is required but not found')
    #     return False

    def __init__(self, subparsers, name: str = None, help='', dependency: Union[str, List[str]] = ''):
        if name is None:
            name = type(self).__name__.lower()
        self.parser = subparsers.add_parser(name, help=help)
        self.parser.set_defaults(func=self.on_command)
        self.on_parser_init(self.parser)
        if subparsers.metavar:
            subparsers.metavar = subparsers.metavar + ', ' + name
        else:
            subparsers.metavar = name

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
