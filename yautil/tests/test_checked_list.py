from unittest import TestCase

from yautil.checked_list import CheckedList


class TestCheckedList(TestCase):
    def test_empty_construction(self):
        lst = CheckedList()
        self.assertEqual(list(lst), [])

    def test_no_on_set_passthrough(self):
        lst = CheckedList(iter=[1, 2, 3])
        self.assertEqual(list(lst), [1, 2, 3])

    def test_on_set_applied_at_construction(self):
        lst = CheckedList(iter=['1', '2'], on_set=int)
        self.assertEqual(list(lst), [1, 2])

    def test_append_applies_on_set(self):
        lst = CheckedList(on_set=int)
        lst.append('5')
        lst.append('6')
        self.assertEqual(list(lst), [5, 6])

    def test_extend_applies_on_set(self):
        lst = CheckedList(on_set=int)
        lst.extend(['1', '2', '3'])
        self.assertEqual(list(lst), [1, 2, 3])

    def test_insert_applies_on_set(self):
        lst = CheckedList(iter=[1, 3], on_set=int)
        lst.insert(1, '2')
        self.assertEqual(list(lst), [1, 2, 3])

    def test_setitem_single_applies_on_set(self):
        lst = CheckedList(iter=[1, 2, 3], on_set=int)
        lst[1] = '99'
        self.assertEqual(list(lst), [1, 99, 3])

    def test_setitem_slice_applies_on_set(self):
        lst = CheckedList(iter=[1, 2, 3, 4], on_set=int)
        lst[1:3] = ['10', '20']
        self.assertEqual(list(lst), [1, 10, 20, 4])

    def test_iadd_applies_on_set(self):
        lst = CheckedList(iter=[1], on_set=int)
        lst += ['2', '3']
        self.assertEqual(list(lst), [1, 2, 3])

    def test_add_returns_new_list(self):
        lst = CheckedList(iter=[1], on_set=int)
        out = lst + ['2', '3']
        self.assertEqual(list(out), [1, 2, 3])
        # Original unchanged
        self.assertEqual(list(lst), [1])

    def test_on_set_raises_propagates(self):
        def reject_negative(v):
            if int(v) < 0:
                raise ValueError(f'negative: {v}')
            return int(v)

        lst = CheckedList(on_set=reject_negative)
        lst.append(1)
        with self.assertRaises(ValueError):
            lst.append(-1)
