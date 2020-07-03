import os
import re

# https://stackoverflow.com/a/241506/3836385
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

def auto_print(string: str):
    if os.fstat(0) == os.fstat(1):
        print(string)
    else:
        print(re.sub(r'\033\[[0-9,;]*[m,K]', '', string))

