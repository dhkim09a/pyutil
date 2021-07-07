from unittest import TestCase, SkipTest

import yautil
import matplotlib.pyplot as plt


class TestPlot(TestCase):
    plot: callable
    pause = .001

    @classmethod
    def setUpClass(cls):
        if cls is TestPlot:
            raise SkipTest("Skip BaseTest tests, it's a base class")
        super(TestPlot, cls).setUpClass()

    def test_basic(self):
        data = [0, 1, 2, 2, 3, 4]
        self.plot(data, block=False)
        plt.pause(self.pause)
        plt.close()

    def test_xlabel(self):
        data = ['test values', 0, 1, 2, 2, 3, 4]
        self.plot(data, block=False)
        plt.pause(self.pause)
        plt.close()

    def test_subfigures(self):
        data = [0, 1, 2, 2, 3, 4]
        self.plot(data, data, block=False)
        plt.pause(self.pause)
        plt.close()

    def test_multi_lines(self):
        data1 = ['test values 1', 0, 1, 2, 2, 3, 4]
        data2 = ['test values 2', 1, 2, 2, 3, 4]
        self.plot((data1, data2), block=False)
        plt.pause(self.pause)
        plt.close()


class TestPlotCdf(TestPlot):

    def __init__(self, *args, **kwargs):
        self.plot = yautil.plot_cdf
        super().__init__(*args, **kwargs)


class TestPlotLinear(TestPlot):

    def __init__(self, *args, **kwargs):
        self.plot = yautil.plot_linear
        super().__init__(*args, **kwargs)


class TestPlotScatter(TestPlot):

    def __init__(self, *args, **kwargs):
        self.plot = yautil.plot_scatter
        super().__init__(*args, **kwargs)


class TestPlotBox(TestPlot):

    def __init__(self, *args, **kwargs):
        self.plot = yautil.plot_box
        super().__init__(*args, **kwargs)


# class TestPlotStack(TestPlot):
#
#     def __init__(self, *args, **kwargs):
#         self.plot = yautil.plot_stack
#         super().__init__(*args, **kwargs)

