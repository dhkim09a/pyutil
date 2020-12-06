from unittest import TestCase

from yautil import MpUtil


def double(x: int) -> int:
    return x * 2


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
