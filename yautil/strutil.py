import os
import re

# https://stackoverflow.com/a/241506/3836385
from itertools import zip_longest


def decomment_cxx(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


def highlight_str(string: str, start: int, end: int):
    color = '\033[{0}m'
    color_str = color.format(31)  # red
    reset_str = color.format(0)

    hl_str = ''
    hl_str += string[0: start]
    hl_str += color_str
    hl_str += string[start: end]
    hl_str += reset_str
    hl_str += string[end:]

    return hl_str


def auto_print(string: str, **kwargs):
    if os.fstat(0) == os.fstat(1):
        print(string, **kwargs)
    else:
        print(re.sub(r'\033\[[0-9,;]*[m,K]', '', string), **kwargs)


def strcompare(left: str, right: str, width: int = None, highlight: bool = True) -> str:
    def __compose_line(ll: str, rl: str, padding: int):
        return str('{:' + str(len(str(ll)) + padding) + '} | {}').format(str(ll), str(rl)) + '\n'

    lls = left.splitlines()
    rls = right.splitlines()

    color_fmt = '\033[{0}m'
    color_red = color_fmt.format(31)  # red
    color_clr = color_fmt.format(0)

    if not width:
        width = max([len(e) for e in lls])

    diff = ""
    for ll, rl in zip_longest(lls, rls):
        ll: str
        rl: str

        padding = width - len(str(ll))

        if ll == rl:
            diff += __compose_line(ll, rl, padding)
            continue

        if highlight and ll and rl:
            hl = False
            i = 0
            while i < min(len(ll), len(rl)):
                if (not hl) and (ll[i] != rl[i]):
                    hl = True
                    ll = ll[:i] + color_red + ll[i:]
                    rl = rl[:i] + color_red + rl[i:]
                    i += len(color_red) + 1
                elif (hl) and (ll[i] == rl[i]):
                    hl = False
                    ll = ll[:i] + color_clr + ll[i:]
                    rl = rl[:i] + color_clr + rl[i:]
                    i += len(color_clr) + 1
                else:
                    i += 1

            if hl:
                ll += color_clr
                rl += color_clr

        diff += __compose_line(ll, rl, padding)
    return diff

