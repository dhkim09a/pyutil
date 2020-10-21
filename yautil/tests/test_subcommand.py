import argparse
from unittest import TestCase

from yautil import Subcommand, SubcommandParser


class TestSubcommand(TestCase):

    def test_basic(self):
        cmd = ''

        class CmdA(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'cmda'

        parser = SubcommandParser()

        parser.add_subcommands(CmdA())

        cmd = 'cmda'
        args = parser.parse_args([cmd])
        parser.exec_subcommands()

    def test_subcommand_naming(self):
        cmd = ''

        class CmdA(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'X'

        parser = SubcommandParser()

        parser.add_subcommands(CmdA(name='X'))

        cmd = 'X'
        args = parser.parse_args([cmd])
        parser.exec_subcommands()

    def test_multiple_subcommand_regs(self):
        cmd = ''

        class CmdA(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'cmda'

        class CmdB(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'cmdb'

        class CmdC(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'cmdc'

        parser = SubcommandParser()

        parser.add_subcommands(CmdA())
        parser.add_subcommands(CmdB(), CmdC())

        cmd = 'cmda'
        argsA = parser.parse_args([cmd])
        parser.exec_subcommands()

        cmd = 'cmdb'
        argsB = parser.parse_args([cmd])
        parser.exec_subcommands()

        cmd = 'cmdc'
        argsC = parser.parse_args([cmd])
        parser.exec_subcommands()

        cmd = 'cmda'
        parser.exec_subcommands(argsA)

    def test_argcomplete(self):
        cmd = ''

        class CmdA(Subcommand):
            def on_parser_init(self, parser: argparse.ArgumentParser):
                pass

            def on_command(self, args):
                assert cmd == 'cmda'

        parser = SubcommandParser(argcomplete=True)

        parser.add_subcommands(CmdA())

        cmd = 'cmda'
        args = parser.parse_args([cmd])
        parser.exec_subcommands()

