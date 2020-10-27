from typing import Union, List


def __plot(*data,
           titles: Union[str, List[str]] = None,
           maxcol: int = 4,
           xlabel: str = None,
           ylabel: str = None,
           xlim: List = None,
           ylim: List = None,
           padding: float = 0.2,
           block: bool = True,
           legend_loc: str = 'best',
           font_family: str = None,
           ):
    """
    Usage examples:

    * Data should be a list of integers

      plot_cdf( [0, 1, 2, 3, 4] )

    * A string element at the beginning of a list is taken as data label.

      plot_cdf( ['example seq.', 0, 1, 2, 3, 4] )

    * Multiple data are plotted on different subfigures.

      plot_cdf( [0, 1, 2, 3, 4], [2, 4, 8, 6, 0] )

    * Data in the same tuple are plotted on the same subfigure.

      plot_cdf( ([0, 1, 2, 3, 4], [2, 4, 8, 6, 0]) )


    :param data: List(s) of integers
    :param titles: Title(s) of each subfigure
    :param maxcol: Maximum number of subfigures in the same row
    :param xlabel: Label (e.g., 'sec')
    :param padding:
    """

    import matplotlib.pyplot as plt

    if not titles:
        titles = []

    fig = plt.figure()
    plt.clf()
    if font_family:
        # 'NanumGothicOTF'
        plt.rc('font', family=font_family)

    for i, subplot_data in enumerate(data):
        if not isinstance(subplot_data, tuple):
            assert isinstance(subplot_data, list)
            subplot_data = (subplot_data,)

        subplot = fig.add_subplot(int((len(data) - 1) / maxcol + 1),
                                  int(min(len(data), maxcol)),
                                  int(i + 1))
        if i < len(titles):
            subplot.title.set_text(titles[i])
        if xlabel:
            subplot.set_xlabel(xlabel)
        if ylabel:
            subplot.set_ylabel(ylabel)
        if xlim:
            subplot.set_xlim(xlim)
        if ylim:
            subplot.set_ylim(ylim)
        plt.subplots_adjust(left=padding, right=1 - padding, top=1 - padding, bottom=padding)

        for line_data in subplot_data:
            assert isinstance(line_data, list)

            if line_data and isinstance(line_data[0], str):
                line_label = line_data[0]
                line_data = line_data[1:]
            else:
                line_label = None

            if not line_data:
                continue

            assert isinstance(line_data[0], tuple)

            x, y = map(list, zip(*line_data))

            subplot.plot(x, y, label=line_label)
    plt.legend(loc=legend_loc)
    plt.show(block=block)


def __modify_line_data(data, modify_line_data: callable) -> list:
    modified_data = []

    for subplot_data in data:
        if not isinstance(subplot_data, tuple):
            subplot_data = (subplot_data,)

        modified_subplot_data = []

        for line_data in subplot_data:
            assert isinstance(line_data, list)

            if line_data and isinstance(line_data[0], str):
                line_label = line_data[0]
                line_data = line_data[1:]
            else:
                line_label = None

            if line_label:
                modified_line_data = [line_label]
            else:
                modified_line_data = []

            modified_line_data.extend(modify_line_data(line_data))

            modified_subplot_data.append(modified_line_data)

        modified_data.append(tuple(modified_subplot_data))

    return modified_data


def plot_cdf(*data,
             titles: Union[str, List[str]] = None,
             maxcol: int = 4,
             xlabel: str = None,
             padding: float = 0.2,
             block: bool = True,
             legend_loc: str = 'best',
             font_family: str = None,
             ):
    """
    Usage examples:

    * Data should be a list of integers

      plot_cdf( [0, 1, 2, 3, 4] )

    * A string element at the beginning of a list is taken as data label.

      plot_cdf( ['example seq.', 0, 1, 2, 3, 4] )

    * Multiple data are plotted on different subfigures.

      plot_cdf( [0, 1, 2, 3, 4], [2, 4, 8, 6, 0] )

    * Data in the same tuple are plotted on the same subfigure.

      plot_cdf( ([0, 1, 2, 3, 4], [2, 4, 8, 6, 0]) )


    :param font_family:
    :param data: List(s) of integers
    :param titles: Title(s) of each subfigure
    :param maxcol: Maximum number of subfigures in the same row
    :param xlabel: Label (e.g., 'sec')
    :param padding:
    :param block:
    :param legend_loc: One of
        'best', 'upper right', 'upper left', 'lower left',
        'lower right', 'right', 'center left', 'center right',
        'lower center', 'upper center', and 'center'
    """

    def __to_cdf(line_data: list) -> list:
        import numpy as np

        # sort the data:
        d = np.sort(line_data)

        # calculate the proportional values of samples
        p = 1. * np.arange(len(line_data)) / (len(line_data) - 1)

        return list(zip(d, p))

    data = __modify_line_data(data, __to_cdf)

    __plot(*data,
           titles=titles,
           maxcol=maxcol,
           xlabel=xlabel,
           ylabel='CDF',
           ylim=[0,1],
           padding=padding,
           block=block,
           legend_loc=legend_loc,
           font_family=font_family,
           )


def plot_linear(*data,
                titles: Union[str, List[str]] = None,
                maxcol: int = 4,
                xlabel: str = None,
                ylabel: str = None,
                xlim: List = None,
                ylim: List = None,
                padding: float = 0.2,
                block: bool = True,
                legend_loc: str = 'best',
                font_family: str = None,
                ):
    """
    Usage examples:

    * Data should be a list of integers

      plot_cdf( [0, 1, 2, 3, 4] )

    * A string element at the beginning of a list is taken as data label.

      plot_cdf( ['example seq.', 0, 1, 2, 3, 4] )

    * Multiple data are plotted on different subfigures.

      plot_cdf( [0, 1, 2, 3, 4], [2, 4, 8, 6, 0] )

    * Data in the same tuple are plotted on the same subfigure.

      plot_cdf( ([0, 1, 2, 3, 4], [2, 4, 8, 6, 0]) )


    :param font_family:
    :param data: List(s) of integers
    :param titles: Title(s) of each subfigure
    :param maxcol: Maximum number of subfigures in the same row
    :param xlabel: Label (e.g., 'sec')
    :param ylabel:
    :param xlim:
    :param ylim:
    :param padding:
    :param block:
    :param legend_loc: One of
        'best', 'upper right', 'upper left', 'lower left',
        'lower right', 'right', 'center left', 'center right',
        'lower center', 'upper center', and 'center'
    """

    def __add_x_values_if_necessarily(line_data: list) -> list:
        if isinstance(line_data[0], tuple):
            return line_data

        return list(zip(range(len(line_data)), line_data))

    data = __modify_line_data(data, __add_x_values_if_necessarily)

    __plot(*data,
           titles=titles,
           maxcol=maxcol,
           xlabel=xlabel,
           ylabel=ylabel,
           xlim=xlim,
           ylim=ylim,
           padding=padding,
           block=block,
           legend_loc=legend_loc,
           font_family=font_family,
           )