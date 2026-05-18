# yautil

Yet Another Python util — a grab bag of helpers grown out of day-to-day work: argparse extensions, file utilities, multiprocessing-friendly caches, Docker shell helpers, plotting wrappers, password/keyring helpers, and a transactional filesystem-mount API.

Failed sub-imports degrade to dummy modules (so `import yautil` works even if one optional dep is missing). Python ≥ 3.11.

## Install

```bash
pip install -e .
```

Requires `sh`, `matplotlib`; optional: `argcomplete`, `keyring`, `tqdm`.

## API

Top-level re-exports — `from yautil import ...`:

### argparse extensions (`yautil.argparse`)

| Symbol                    | Purpose                                                                       |
| ------------------------- | ----------------------------------------------------------------------------- |
| `OverridingAppendAction`  | `append`-style action where a later flag replaces the accumulated list.       |
| `SplitAppendAction`       | `append` that splits each value on a delimiter (e.g. `a,b,c`).                |
| `SmartAppendAction`       | Heuristic combination of override + split semantics.                          |
| `ChoiceComb`              | `list[str]` subclass used as `choices=` to allow comma-separated combinations.|
| `WarningAction`           | `--warning=foo,bar` action with allowed-value validation.                     |

### Files (`yautil.file`)

| Symbol                                                            | Purpose                                                  |
| ----------------------------------------------------------------- | -------------------------------------------------------- |
| `find(root, ...)`                                                 | Non-recursive find with name patterns / type filter.     |
| `find_recursive(root, name_patterns=None, ignored_dirs=None, type='any', depth=-1, sort=False)` | Recursive find with prune list.                          |
| `remove_contents(folder)`                                         | Delete every entry inside `folder` without removing it.  |
| `overwrite(src, dst)`                                             | Replace `dst` with `src` atomically.                     |
| `get_memtmpdir(suffix=None, prefix=None, dir=None)`               | `TemporaryDirectory` on `/dev/shm` (or `tmpfs`) when available. |
| `Writable`                                                        | File-like wrapper that proxies writes; useful for piping output. |

### Decorators (`yautil.decorators`)

| Symbol                | Purpose                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `static_vars(**kw)`   | Attach mutable "static" attributes to a function on first call.  |

### Events (`yautil.event`)

| Symbol            | Purpose                                                        |
| ----------------- | -------------------------------------------------------------- |
| `Event`           | Listenable event object (`+= handler` to subscribe, call to fire). |
| `EventGenerator`  | Mixin / factory that declares named `Event`s on an object.     |

### Printing (`yautil.print`)

| Symbol                                                                | Purpose                                              |
| --------------------------------------------------------------------- | ---------------------------------------------------- |
| `decomment_cxx(text)`                                                 | Strip `//` and `/* */` comments from C/C++/Java text.|
| `auto_print(string, max_len=-1, **kwargs)`                            | `print` with auto-truncation past `max_len`.         |
| `strcompare(left, right, width=-1, highlight=True) -> str`            | Side-by-side diff string with ANSI highlighting.     |

### Plotting (`yautil.plot`)

Thin matplotlib wrappers — all accept `*data` and a common set of styling kwargs.

| Symbol         | Plot type                              |
| -------------- | -------------------------------------- |
| `plot_cdf`     | Cumulative distribution function.      |
| `plot_linear`  | Line plot.                             |
| `plot_scatter` | Scatter plot.                          |
| `plot_box`     | Box plot.                              |
| `plot_stack`   | Stacked area / bar plot.               |

### Caches

| Symbol                                            | Purpose                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| `lru_cache(...)` (`yautil.lru_cache_ext`)         | Like `functools.lru_cache` but hashes `list`/`dict` arguments too. |
| `PersistentCache` (`yautil.persistent_cache`)     | Disk-backed cache under `~/.cache/`; survives process restarts.  |

### Passwords (`yautil.passwd`)

| Symbol                                                                          | Purpose                                                            |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `create_w_password(...)`                                                        | Build an object that requires interactive password unlock.         |
| `create_w_secrets(...)`                                                         | Build an object that pulls secrets from a password-protected store.|

(See the module for the exact constructor signatures — both wrap `keyring` and an encrypted local secrets file.)

### Docker shell (`yautil.docker_sh`)

| Symbol                | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `docker_sh(...)`      | `sh`-compatible Command that runs inside a built/pulled Docker image, with bind mounts, user-id pass-through, and interactive TTY support. |
| `AuthorizationError`  | Raised when the daemon refuses (e.g. missing `docker login`).           |

### Git (`yautil.git`)

| Symbol                                                                                 | Purpose                                                |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `git_expand(repo, dest, *checkout_targets, ignore_errors=False, iter=False)`           | Shallow-clone (or update) `repo` into `dest` for each `checkout_target` (branch/tag/sha). |
| `git_merge_file(...)`                                                                  | Three-way file merge wrapping `git merge-file`.        |

### IO (`yautil.io`)

| Symbol               | Purpose                                                              |
| -------------------- | -------------------------------------------------------------------- |
| `FilteredTextIO`     | `TextIO` proxy that runs every write through a `WriteCallback`.      |

### Shell interop (`yautil.pysh`)

| Symbol                                  | Purpose                                                              |
| --------------------------------------- | -------------------------------------------------------------------- |
| `compile_shargs(*args, **kwargs)`       | Pack Python call args into the `(args, kwargs)` form `sh.Command` expects. |
| `get_cmd_args(cmd)`                     | Recover the argv that produced a given `sh.Command` invocation.      |

### Mount API (`yautil.mount`)

Filesystem-mount abstraction for disk images / archives, plus high-level `mount` / `extract` / `archive` helpers.

```python
from yautil.mount import mount, extract, archive, DiskImage, LinuxDiskImage
```

| Symbol           | Purpose                                                                |
| ---------------- | ---------------------------------------------------------------------- |
| `mount(target)`  | Context manager that mounts `target` and yields the mount point.       |
| `extract(target, dest)` | Extract contents of `target` into `dest`.                       |
| `archive(src, dest, type)` | Build an archive of `src` at `dest`.                         |
| `Mountable`      | Base class for anything that can be mounted (loop devices, archives).  |
| `Archive`        | `Mountable` subclass for archive formats.                              |
| `MountableType`, `ArchiveType` | Enums of supported types.                                |
| `DiskImage`, `LinuxDiskImage`  | Concrete `Mountable` for raw/Linux disk images (uses `udisksctl`). |
