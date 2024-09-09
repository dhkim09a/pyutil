from typing import Any, Callable, Generic, Iterator, TypeVar
import collections.abc

T = TypeVar('T')

class CheckedList(list, collections.abc.MutableSequence, Generic[T]):
    on_set: Callable[[Any], T]

    def __init__(self, iter: Iterator | None = None, on_set: Callable[[Any], T] | None = None):
        self.__on_set = on_set
        if not iter is None:
            self.extend(iter) # This validates the arguments...

    def insert(self, i, v):
        return super(CheckedList, self).insert(i, self.__on_set(v) if self.__on_set else v)

    def append(self, v):
        return super(CheckedList, self).append(self.__on_set(v) if self.__on_set else v)

    def extend(self, t):
        return super(CheckedList, self).extend([ self.__on_set(v) if self.__on_set else v for v in t ])

    def __add__(self, t): # This is for something like `CheckedList(validator, [1, 2, 3]) + list([4, 5, 6])`...
        return super(CheckedList, self).__add__([ self.__on_set(v) if self.__on_set else v for v in t ])

    def __iadd__(self, t): # This is for something like `l = CheckedList(validator); l += [1, 2, 3]`
        return super(CheckedList, self).__iadd__([ self.__on_set(v) if self.__on_set else v for v in t ])

    def __setitem__(self, i, v):
        if isinstance(i, slice):
            return super(CheckedList, self).__setitem__(i, [ self.__on_set(v1) if self.__on_set else v1 for v1 in v ]) # Extended slice...
        else:
            return super(CheckedList, self).__setitem__(i, self.__on_set(v) if self.__on_set else v)

    def __setslice__(self, i, j, t): # NOTE: extended slices use __setitem__, passing in a tuple for i
        return super(CheckedList, self).__setslice__(i, j, [ self.__on_set(v) if self.__on_set else v for v in t ]) # type: ignore
