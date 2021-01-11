from unittest import TestCase

from yautil import MpUtil


def double(x: int) -> int:
    return x * 2


class Object:
    i: int
    s: str
    d: dict
    l: list


def new_obj() -> Object:
    o = Object()
    o.i = 0
    o.s = 'object'
    o.d = {'a': 1, 'b': 2}
    o.l = ['c', 'd']

    return o


class TestMpUtil(TestCase):

    def test_basic(self):
        data = [0, 1, 2, 3, 4, 5]

        with MpUtil(total=len(data), pbar=False) as mp:
            for d in data:
                mp.schedule(double, d)
            results = mp.wait()

        for y in [0, 2, 4, 6, 8, 10]:
            assert y in results

    # def test_ordered(self):
    #     data = [0, 1, 2, 3, 4, 5]
    #
    #     with MpUtil(total=len(data), ordered=True) as mp:
    #         for d in data:
    #             mp.schedule(double, d)
    #         results = mp.wait()
    #
    #     for i, y in enumerate([0, 2, 4, 6, 8, 10]):
    #         assert y == results[i]

    def test_call_twice(self):
        self.test_basic()
        self.test_basic()

    def test_obj_ret(self):
        total = 10
        with MpUtil(total=total, pbar=False) as mp:
            for i in range(total):
                mp.schedule(new_obj)
            results = mp.wait()
        assert len(results) == total
        for o in results:
            assert isinstance(o, Object)
            assert o.i == 0
            assert o.s == 'object'
            assert o.d['a'] == 1
            assert o.d['b'] == 2
            assert len(o.l) == 2
            assert o.l[0] == 'c'
            assert o.l[1] == 'd'
