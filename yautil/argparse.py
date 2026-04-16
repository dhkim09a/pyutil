
import argparse
import re
from typing import Iterable

from .checked_list import CheckedList


class OverridingAppendAction(argparse._AppendAction):
    first_call: bool = True

    def __call__(self, parser, namespace, values, option_string=None):
        if self.first_call:
            setattr(namespace, self.dest, [])
            self.first_call = False

        super().__call__(parser, namespace, values, option_string)


class SplitAppendAction(argparse._AppendAction):
    first_call: bool = True

    def __call__(self, parser, namespace, values, option_string=None):
        if self.first_call:
            setattr(namespace, self.dest, [])
            self.first_call = False

        if not isinstance(values, str):
            super().__call__(parser, namespace, values, option_string)
            return

        for v in values.split(','):
            super().__call__(parser, namespace, v.strip(), option_string)


class ChoiceComb(list[str]):
    metaopts: set[str]
    opts: list[str]

    def __init__(self, opts: Iterable[str], no_opts: bool = False):
        self.metaopts = {'all'}
        self.opts = list(opts)
        super(ChoiceComb, self).__init__([*self.metaopts] + list(opts) + (['no-' + c for c in opts] if no_opts else []))

    def __contains__(self, o: object) -> bool:
        return all(super(ChoiceComb, self).__contains__(c) for c in str(o).split(','))


class WarningOption(CheckedList[str]):
    __choices: ChoiceComb | None

    def attrname(self, optname: str) -> str:
        return re.sub(r'[^a-zA-Z0-9]', '_', optname).strip('_')

    def on_set(self, value: str) -> str:
        # print(f'on_set called for {value}')
        if self.__choices is None:
            return value

        if not isinstance(value, str):
            return value

        if value == 'all':
            # print(f'all!')
            for c in self.__choices.opts:
                # print(f'setting attr {self.attrname(c)}')
                setattr(self, self.attrname(c), True)

        elif value.startswith('no-'):
            aname = self.attrname(value[3:])
            assert hasattr(self, aname)
            setattr(self, aname, False)

        else:
            aname = self.attrname(value)
            assert hasattr(self, aname)
            setattr(self, aname, True)

        return value

    def __init__(self, *args, choices: ChoiceComb | None = None, **kwargs):
        self.__choices = choices
        if choices is not None:
            for c in choices.opts:
                # print(f'setting attr {self.attrname(c)}')
                setattr(self, self.attrname(c), None)
        super(WarningOption, self).__init__(*args, on_set=self.on_set, **kwargs)


class SmartAppendAction(argparse._AppendAction):
    """
    Action that supports:
    1. Appending values to a list
    2. Splitting comma-separated values
    3. Choice validation with 'all' option
    4. Default values that can be overridden
    """
    choices: ChoiceComb | None

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

        # Process choices
        if choices is not None:
            choices = ChoiceComb(choices, no_opts=False)
        
        self.choices = choices
        self.first_call = True

        super(SmartAppendAction, self).__init__(
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
        # Initialize the list on first call to override default value
        if self.first_call:
            setattr(namespace, self.dest, [])
            self.first_call = False

        # Get the current items
        items = getattr(namespace, self.dest, None)
        if items is None:
            items = []
        
        # Handle values - split comma-separated strings
        values_to_add = []
        if isinstance(values, str):
            # Split comma-separated values
            for v in values.split(','):
                stripped_v = v.strip()
                # Handle 'all' option
                if stripped_v == 'all' and self.choices is not None:
                    # Add all choices (except meta options like 'all' itself)
                    values_to_add.extend(list(self.choices.opts))
                else:
                    values_to_add.append(stripped_v)
        else:
            # Handle non-string values (lists, etc.)
            if isinstance(values, (list, tuple)):
                for v in values:
                    if isinstance(v, str) and ',' in v:
                        # Split comma-separated values in lists too
                        for sv in v.split(','):
                            values_to_add.append(sv.strip())
                    else:
                        values_to_add.append(v)
            else:
                values_to_add.append(values)
        
        # Validate choices if specified
        if self.choices is not None:
            for v in values_to_add:
                if v not in self.choices:
                    raise ValueError(f"Invalid choice: {v} (choose from {self.choices})")
        
        # Extend the items list
        items.extend(values_to_add)
        setattr(namespace, self.dest, items)


class WarningAction(argparse.Action):
    never_called: bool
    choices: ChoiceComb | None

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
        self.never_called = True

        if nargs == 0:
            raise ValueError('nargs for append actions must be != 0; if arg '
                             'strings are not supplying the value to append, '
                             'the append const action may be more appropriate')
        if const is not None and nargs != argparse.OPTIONAL:
            raise ValueError('nargs must be %r to supply const' % argparse.OPTIONAL)

        if choices is not None:
            choices = ChoiceComb(choices, no_opts=True)

        if not metavar:
            metavar = 'WARNING_OPTS'

        super(WarningAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            const=const,
            default=WarningOption(default, choices=choices),
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        if self.never_called:
            setattr(namespace, self.dest, self.default)
            self.never_called = False

        items = getattr(namespace, self.dest, None)
        # items = argparse._copy_items(items) # type: ignore
        assert isinstance(items, WarningOption)
        items.extend([v.strip() for v in values.split(',')]) # type: ignore
        setattr(namespace, self.dest, items)
