import multiprocessing as mp
import signal
import sys
import traceback
import uuid
from typing import List, Tuple

from tqdm import tqdm

_obj_idmap: dict = {}


# https://gist.github.com/EdwinChan/3c13d3a746bb3ec5082f
# globalize decorator for inner functions
def globalize(func):
    def result(*args, **kwargs):
        return func(*args, **kwargs)

    result.__name__ = result.__qualname__ = uuid.uuid4().hex
    setattr(sys.modules[result.__module__], result.__name__, result)
    return result


# Shortcut to multiprocessing's logger
def error(msg, *args):
    return mp.get_logger().error(msg, *args)


class LogExceptions(object):
    def __init__(self, callable):
        self.__callable = callable

    def __call__(self, *args, **kwargs):
        try:
            result = self.__callable(*args, **kwargs)

        except Exception as e:
            # Here we add some debugging help. If multiprocessing's
            # debugging is on, it will arrange to log the traceback
            error(traceback.format_exc())
            # Re-raise the original exception so the Pool worker can
            # clean up
            raise

        # It was fine, give a normal answer
        return result


def _sighandler(signum, frame):
    if signum == signal.SIGALRM:
        signal.signal(signal.SIGALRM, _sighandler)
        raise TimeoutError('MpUtil: Timeout expired')
    else:
        raise Exception('MpUtil: Unexpected signal received: ' + str(signum))


def _on_done(result):
    self_id, count, ret = result
    # print('done: self_id: ' + str(self_id) + ', count: ' + str(count) + ', res: ' + str(ret))

    self = _obj_idmap[self_id]

    with self.free.get_lock():
        self.results.extend(ret)
        while ret:
            ret.pop()
        self.buffer.append(ret)
        if self.pbar is not None:
            self.pbar.update(count)
        self._done += count

        self.free.value += 1
        self.free_cond.notify()


def _func_wrapper(self_id, ret: list, arglist: List[Tuple]):
    count: int = 0
    # print('wrapper: id: ' + str(self_id) + ', ret: ' + str(ret))
    self = _obj_idmap[self_id]

    if self.task_timeout > 0:
        signal.signal(signal.SIGALRM, _sighandler)

    for argset in arglist:
        func, args, kwargs, _siz = argset
        # print('wrapper: self_id: ' + str(self_id) + ', func: ' + str(func) + ', args: ' + str(args) + ', kwargs: ' + str(kwargs))
        if self.task_timeout > 0:
            signal.alarm(self.task_timeout)
        try:
            if self.arg0:
                result = func(*args, arg0=self.arg0, **kwargs)
            else:
                result = func(*args, **kwargs)
            if self.task_timeout > 0:
                signal.alarm(0)
        except Exception as e:
            traceback.print_tb(e.__traceback__)
            print('MpUtil error: ' + str(e) + ' while processing *args: ' + str(args) + ', **kwargs: ' + str(kwargs))
            result = None

        if result is not None:
            try:
                ret.append(result)
            except Exception as e:
                print('MpUtil error: can\'t handle results from ' + str(func) + '(' + str(args) + ', ' + str(kwargs) + '). ' + str(e))
        count += _siz

    return self_id, count, ret


class MpUtil:
    mpctx: mp
    ctx: mp.Manager
    pool: mp.Pool
    pbar: tqdm
    free = None
    queue: list
    results: list
    buffer: List[List]
    id = None
    __maxchunksize: int
    task_timeout: int
    arg0: object
    __total: int
    _done: int

    def __init__(self, processes: int = 0, maxchunksize: int = 1, total: int = 0, desc: str = "", task_timeout=0,
                 arg0: object = None, pbar: bool = True):
        if processes == 0:
            processes = mp.cpu_count()

        if 'fork' in mp.get_all_start_methods():
            self.mpctx = mp.get_context('fork')
        else:
            raise OSError('\'fork\' starting method is required from the multiprocessing module')

        self.ctx = self.mpctx.Manager()
        self.free = self.mpctx.Value('i', processes)
        self.free_cond = self.mpctx.Condition(self.free.get_lock())

        self.queue = []
        self.results = self.ctx.list([])
        self.pbar = tqdm(total=total, desc=desc) if pbar else None
        self.__total = total
        self._done = 0

        self.buffer = self.ctx.list()
        for _ in range(processes + 1):
            self.buffer.append(self.ctx.list())

        self.maxchunksize = maxchunksize
        self.task_timeout = task_timeout
        self.arg0 = arg0

        self.id = id(self)
        _obj_idmap[self.id] = self

        self.pool = self.mpctx.Pool(processes=processes)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __del__(self):
        if _obj_idmap:
            _obj_idmap.pop(self.id)

    @property
    def maxchunksize(self) -> int:
        return self.__maxchunksize
    
    @maxchunksize.setter
    def maxchunksize(self, val: int):
        self.__maxchunksize = max(val, 1)

    @property
    def total(self) -> int:
        return self.__total

    @total.setter
    def total(self, val: int):
        self.__total = val
        if self.pbar is not None:
            self.pbar.total = val

    @property
    def done(self) -> int:
        return self._done

    def __flush_once_locked(self, max_n: int = None, nonblock=False):
        if nonblock and self.free.value == 0:
            return False
        while self.free.value == 0:
            self.free_cond.wait()
        ret: list = self.buffer.pop()
        self.pool.apply_async(LogExceptions(_func_wrapper), (self.id, ret, self.queue[:self.maxchunksize],), callback=_on_done)
        self.queue = self.queue[self.maxchunksize:]
        self.free.value -= 1
        return True
                
    def _flush(self, max_n: int = None, nonblock=False, locked=False):
        if locked:
            while self.queue and self.__flush_once_locked(nonblock=nonblock):
                pass
        else:
            with self.free.get_lock():
                while self.queue and self.__flush_once_locked(nonblock=nonblock):
                    pass

    def flush(self, max_n: int = None, nonblock=False):
        return self._flush(max_n=max_n, nonblock=nonblock, locked=False)
        
    def schedule(self, func: callable, *args, _siz: int = 1, _nonblock=False, **kwargs):
        with self.free.get_lock():
            self.queue.append((func, args, kwargs, _siz))

            if len(self.queue) < self.maxchunksize:
                return

            self._flush(nonblock=_nonblock, locked=True)

    def wait(self):
        self.flush()
        self.pool.close()
        self.pool.join()
        if self.pbar is not None:
            self.pbar.close()
        self.mpctx.log_to_stderr()
        return self.results
