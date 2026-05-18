import io
import sys
from contextlib import redirect_stdout
from unittest import TestCase
from unittest.mock import patch

from yautil.print import decomment_cxx, highlight_str, auto_print, strcompare


class TestDecommentCxx(TestCase):
    def test_strips_line_comment(self):
        src = "int x = 1; // a comment\nint y = 2;\n"
        result = decomment_cxx(src)
        self.assertNotIn('a comment', result)
        self.assertIn('int x = 1;', result)
        self.assertIn('int y = 2;', result)

    def test_strips_block_comment(self):
        src = "int x = 1; /* block\ncomment */ int y;"
        result = decomment_cxx(src)
        self.assertNotIn('block', result)
        self.assertNotIn('comment', result)
        self.assertIn('int x = 1;', result)

    def test_preserves_string_literals(self):
        src = 'const char *s = "// not a comment";\n'
        result = decomment_cxx(src)
        self.assertIn('// not a comment', result)

    def test_preserves_char_literals(self):
        src = "char c = '/';\n"
        result = decomment_cxx(src)
        self.assertIn("'/'", result)

    def test_no_comment_passthrough(self):
        src = "no_comments_here = 42;\n"
        self.assertEqual(decomment_cxx(src), src)


class TestHighlightStr(TestCase):
    def test_inserts_red_and_reset_codes(self):
        result = highlight_str('abcdef', 2, 4)
        self.assertIn('\033[31m', result)
        self.assertIn('\033[0m', result)
        # Original characters all still present
        self.assertIn('ab', result)
        self.assertIn('cd', result)
        self.assertIn('ef', result)

    def test_highlights_entire_string(self):
        result = highlight_str('xyz', 0, 3)
        self.assertTrue(result.startswith('\033[31m'))
        self.assertIn('xyz', result)


class TestAutoPrint(TestCase):
    def test_truncates_when_max_len(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            auto_print('hello world', max_len=5)
        self.assertIn('hello', buf.getvalue())
        self.assertNotIn('world', buf.getvalue())

    def test_strips_ansi_codes_when_tty_redirected(self):
        # When fstat(0) != fstat(1), ANSI codes are stripped.
        buf = io.StringIO()
        with patch('os.fstat', side_effect=lambda fd: fd):
            with redirect_stdout(buf):
                auto_print('\033[31mred\033[0m')
        self.assertEqual(buf.getvalue().strip(), 'red')


class TestStrcompare(TestCase):
    def test_identical_lines_no_color(self):
        result = strcompare('hello', 'hello', highlight=False)
        # Should contain hello on both sides
        self.assertIn('hello', result)
        # No red color since identical
        self.assertNotIn('\033[31m', result)

    def test_different_lines_highlighted(self):
        result = strcompare('hello', 'hxllo', highlight=True)
        self.assertIn('\033[31m', result)
        self.assertIn('\033[0m', result)

    def test_multiline_difference(self):
        result = strcompare('line1\nline2', 'line1\nliney')
        # First identical line passes through; second line has ANSI codes
        # inserted at the diff position so substring match must be loose.
        self.assertIn('line1', result)
        self.assertIn('\033[31m', result)  # diff highlight is present
        # Both ends of the divergent line survive in fragments
        self.assertIn('line', result)
        self.assertIn('2', result)
        self.assertIn('y', result)
