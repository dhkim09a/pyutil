from typing import Callable, TextIO


WriteCallback = Callable[[str], str | None]


class FilteredTextIO(TextIO):
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
        if isinstance(__buffer, bytes) or isinstance(__buffer, bytearray):
            __buffer = __buffer.decode('utf-8')

        lines = (self.leftover + __buffer).splitlines(keepends=True)

        if lines[-1].endswith('\n'):
            to_print = ''.join(lines)
            self.leftover = ''
        else:
            to_print = ''.join(lines[:-1])
            self.leftover = lines[-1]
        
        if not to_print:
            return

        to_write: str | None = self.on_write(to_print)

        if to_write is None:
            return

        self.dest.write(to_write)
        self.dest.flush()

    def writelines(self, __lines) -> None:
        self.dest.writelines(__lines)
        self.dest.flush()