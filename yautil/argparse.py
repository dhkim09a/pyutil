
import argparse


class OverridingAppendAction(argparse._AppendAction):
    first_call: bool = True

    def __call__(self, parser, namespace, values, option_string=None):
        if self.first_call:
            setattr(namespace, self.dest, [])
            self.first_call = False

        super().__call__(parser, namespace, values, option_string)


class ChoiceComb(set):
    def __contains__(self, o: object) -> bool:
        return all(super(ChoiceComb, self).__contains__(c) for c in str(o).split(','))


class WarningAction(argparse.Action):
    first_call: bool = True

    def __init__(self,
                 option_strings,
                 dest,
                 nargs=None,
                 const=None,
                 default=None,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):
        if nargs == 0:
            raise ValueError('nargs for append actions must be != 0; if arg '
                             'strings are not supplying the value to append, '
                             'the append const action may be more appropriate')
        if const is not None and nargs != argparse.OPTIONAL:
            raise ValueError('nargs must be %r to supply const' % argparse.OPTIONAL)

        if choices:
            choices = ChoiceComb(list(choices) + ['no-' + c for c in choices])

        if not metavar:
            metavar = 'WARNING_OPTS'

        super(WarningAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            const=const,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        if self.first_call:
            setattr(namespace, self.dest, [])
            self.first_call = False

        items = getattr(namespace, self.dest, None)
        items = argparse._copy_items(items) # type: ignore
        items.extend(values.split(',')) # type: ignore
        setattr(namespace, self.dest, items)
