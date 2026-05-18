from unittest import TestCase

from yautil.lru_cache_ext import hash_dict, hash_item, hash_list, lru_cache


class TestHashing(TestCase):
    def test_hash_item_int(self):
        self.assertEqual(hash_item(5), hash(5))

    def test_hash_item_str(self):
        self.assertEqual(hash_item('abc'), hash('abc'))

    def test_hash_item_list_delegates(self):
        # List isn't natively hashable; goes through hash_list path
        result = hash_item([1, 2, 3])
        self.assertEqual(result, hash_list([1, 2, 3]))

    def test_hash_item_dict_delegates(self):
        result = hash_item({'a': 1})
        self.assertEqual(result, hash_dict({'a': 1}))

    def test_hash_item_set_delegates(self):
        # set is in (list, set, tuple) branch
        result = hash_item({1, 2, 3})
        self.assertEqual(result, hash_list([1, 2, 3]))

    def test_hash_item_unhashable_raises(self):
        class NoHash:
            __hash__ = None

        with self.assertRaises(TypeError):
            hash_item(NoHash())

    def test_hash_list_same_for_equal_lists(self):
        self.assertEqual(hash_list([1, 2, 3]), hash_list([1, 2, 3]))

    def test_hash_list_differs_by_order(self):
        self.assertNotEqual(hash_list([1, 2, 3]), hash_list([3, 2, 1]))


class TestLruCacheDecorator(TestCase):
    def test_caches_simple_call(self):
        call_count = [0]

        @lru_cache(maxsize=10)
        def f(x):
            call_count[0] += 1
            return x * 2

        self.assertEqual(f(5), 10)
        self.assertEqual(f(5), 10)
        self.assertEqual(call_count[0], 1)

    def test_different_args_dont_collide(self):
        @lru_cache(maxsize=10)
        def f(x):
            return x * 2

        self.assertEqual(f(2), 4)
        self.assertEqual(f(3), 6)
        self.assertEqual(f(2), 4)

    def test_handles_list_argument(self):
        # Stdlib lru_cache can't hash lists; the extension can.
        @lru_cache(maxsize=10)
        def f(xs):
            return sum(xs)

        self.assertEqual(f([1, 2, 3]), 6)
        self.assertEqual(f([1, 2, 3]), 6)

    def test_handles_dict_argument(self):
        @lru_cache(maxsize=10)
        def f(d):
            return sum(d.values())

        self.assertEqual(f({'a': 1, 'b': 2}), 3)

    def test_cache_clear(self):
        call_count = [0]

        @lru_cache(maxsize=10)
        def f(x):
            call_count[0] += 1
            return x

        f(1)
        f(1)
        self.assertEqual(call_count[0], 1)
        f.cache_clear()
        f(1)
        self.assertEqual(call_count[0], 2)
