from typing import Callable, TextIO


WriteCallback = Callable[[str], str | None]


class FilteredTextIO(object):
    dest: TextIO
    on_write: WriteCallback
    leftover: str

    def __init__(self, dest: TextIO, on_write: WriteCallback):
        super().__init__()
        self.dest = dest
        self.on_write = on_write
        self.leftover = ''

    def __getattr__(self, item):
        if item == 'fileno':
            return None
        return getattr(self.dest, item)

    def write(self, __buffer):
        if len(l := __buffer.rsplit('\n', 1)) == 2:
            to_print, leftover = l
        else:
            self.leftover = l[0]
            return

        to_write: str | None = self.on_write(self.leftover + to_print + '\n')

        if to_write is None:
            return

        self.dest.write(to_write)
        self.dest.flush()

        self.leftover = leftover

    def writelines(self, __lines) -> None:
        self.dest.writelines(__lines)
        self.dest.flush()