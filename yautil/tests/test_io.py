import io
from unittest import TestCase

from yautil.io import FilteredTextIO


class TestFilteredTextIO(TestCase):
    def test_passthrough_when_callback_returns_same(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s)
        f.write('hello\n')
        self.assertEqual(sink.getvalue(), 'hello\n')

    def test_callback_transforms_text(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s.upper())
        f.write('hello\n')
        self.assertEqual(sink.getvalue(), 'HELLO\n')

    def test_callback_returning_none_drops(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: None)
        f.write('drop me\n')
        self.assertEqual(sink.getvalue(), '')

    def test_partial_line_buffered_until_newline(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s)
        f.write('partial')
        # No newline yet → nothing written
        self.assertEqual(sink.getvalue(), '')
        f.write(' rest\n')
        self.assertEqual(sink.getvalue(), 'partial rest\n')

    def test_accepts_bytes_input(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s)
        f.write(b'bytes line\n')
        self.assertEqual(sink.getvalue(), 'bytes line\n')

    def test_writelines_delegates(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s)
        f.writelines(['a\n', 'b\n'])
        # writelines passes through directly without filtering
        self.assertEqual(sink.getvalue(), 'a\nb\n')

    def test_getattr_proxies_to_dest(self):
        sink = io.StringIO()
        f = FilteredTextIO(sink, on_write=lambda s: s)
        # closed is an attribute of StringIO
        self.assertFalse(f.closed)
