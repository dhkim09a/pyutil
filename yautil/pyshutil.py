import os
from typing import Tuple

import sh


def get_cmd_args(cmd: sh.Command):
    args = [cmd._path]
    if cmd._partial:
        args.extend(cmd._partial_baked_args)
    return [e.decode('utf-8') for e in args]


def compile_shargs(*args, **kwargs) -> Tuple[list, dict]:
    shcmd = sh.Command('/bin/ls').bake(*args, **kwargs)
    return (
        [a.decode('utf-8') for a in shcmd._partial_baked_args],
        {'_' + k: i for k, i in shcmd._partial_call_args.items()}
    )


def source(path: str, cmd=None, _cwd='.', _env=os.environ) -> dict:
    ret = {}
    if cmd is None:
        envs = sh.bash('-c', 'source ' + path + ' >/dev/null && env', _cwd=_cwd, _env=_env)
    else:
        envs = sh.bash('-c', 'source ' + path + ' >/dev/null && ' + cmd + ' >/dev/null && env', _cwd=_cwd, _env=_env)
    for env in envs.splitlines():
        env: str
        var, val = env.split('=', 1)
        ret[var] = val
    return ret
