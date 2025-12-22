from ast import literal_eval
import getpass
import os
from os import path as _p
import readline
import tempfile
from typing import Any, Callable, TypeVar

import keyring
import keyring.errors
import keyring.testing
import sh

T = TypeVar('T')


def rlinput(prompt, prefill=''):
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return input(prompt)
    finally:
        readline.set_startup_hook(None)


def load_secrets(password: str, path: str) -> dict[str, str] | None:
    if not _p.isfile(path):
        return

    outfile = tempfile.NamedTemporaryFile()
    os.chmod(outfile.name, 0o600)

    with open(path, 'rb') as encrypted_file:
        try:
            sh.openssl.enc( # type: ignore[attr-defined]
                aes_256_cbc=True, out=outfile.name, salt=True, d=True, k=password,
                _in=encrypted_file, _long_sep=' ', _long_prefix='-',
            )
        except Exception as e:
            print('error')
            return

    with open(outfile.name, 'r') as f:
        secrets = literal_eval(f.read())
        return secrets if isinstance(secrets, dict) else None


def save_secrets(password: str, path: str, secrets: dict[str, str]):
    outfile = tempfile.NamedTemporaryFile()
    os.chmod(outfile.name, 0o600)

    with open(outfile.name, 'w') as f:
        f.write(repr(secrets))

    try:
        sh.openssl.enc( # type: ignore[attr-defined]
            aes_256_cbc=True, out=path, salt=True, k=password,
            _in=outfile, _long_sep=' ', _long_prefix='-',
        )
    except Exception as e:
        print('error')
        return


def __create_w_secrets(
    constructor: Callable[[dict[str, str]], T | None],
    secret_desc: dict[str, bool],
    load_secrets: Callable[[], dict[str, str]],
    save_secrets: Callable[[dict[str, str]], Any],
    retry: int = 2,
) -> T | None:
    new_pw: bool = False
    failed: bool = False

    secrets: dict[str, str] = load_secrets() or {}

    if retry <= 0:
        retry = 1
    else:
        retry += 1

    while retry > 0:
        if failed or any(k not in secrets for k in secret_desc):
            for k, is_secret in secret_desc.items():
                if is_secret:
                    secrets[k] = getpass.getpass(f'{k}: ')
                else:
                    secrets[k] = rlinput(f'{k}: ', secrets.get(k, ''))
            new_pw = True

        if (result := constructor(secrets)) is not None:
            if new_pw:
                save_secrets(secrets)
            return result

        retry -= 1
        failed = True


def ensure_unlocked():
    try:
        keyring.get_password('__test__', '__test__')
    except keyring.errors.InitError:
        gnome_keyring = sh.Command('gnome-keyring-daemon')
        gnome_keyring(r=True, d=True, unlock=True, _in=getpass.getpass(f'Password of {getpass.getuser()}'))
        keyring.get_password('__test__', '__test__')


def create_w_secrets(
    constructor: Callable[[dict[str, str]], T | None],
    servicename: str,
    secret_desc: dict[str, bool],
    keyring_username: str = '',
    retry: int = 2,
) -> T | None:
    keyring_username = keyring_username or getpass.getuser()
    secrets_path: str = _p.expanduser(f'~/.{servicename}.secrets')

    def construct_masterkey(secrets: dict[str, str]) -> str | None:
        masterkey = secrets.get('masterkey')
        if not masterkey:
            return
        if _p.exists(secrets_path) and load_secrets(masterkey, secrets_path) is None:
            return
        return masterkey

    ensure_unlocked()

    masterkey = __create_w_secrets(
        constructor = construct_masterkey,
        secret_desc = {'masterkey': True},
        retry = retry,
        load_secrets = lambda: {'masterkey': p} if (p := keyring.get_password(servicename, keyring_username)) else {},
        save_secrets = lambda secrets: keyring.set_password(servicename, keyring_username, secrets['masterkey']),
    )

    if not masterkey:
        return

    return __create_w_secrets(
        constructor = constructor,
        secret_desc = secret_desc,
        retry = retry,
        load_secrets = lambda: load_secrets(masterkey, secrets_path) or {},
        save_secrets = lambda secrets: save_secrets(masterkey, secrets_path, secrets),
    )


def create_w_secrets2(
    constructor: Callable[[dict[str, str]], T | None],
    servicename: str,
    secret_desc: dict[str, bool],
    retry: int = 2,
) -> T | None:
    ensure_unlocked()

    return __create_w_secrets(
        constructor = constructor,
        secret_desc = secret_desc,
        retry = retry,
        load_secrets = lambda: {k: v for k in secret_desc if (v := keyring.get_password(servicename, k))},
        save_secrets = lambda secrets: [keyring.set_password(servicename, k, v) for k, v in secrets.items()],
    )


def create_w_password(
    constructor: Callable[[str], T | None],
    servicename: str,
    keyring_username: str = '',
    retry: int = 2,
) -> T | None:
    def _constructor(secrets: dict[str, str]) -> T | None:
        return constructor(secrets['password'])
    return create_w_secrets(
        _constructor,
        servicename,
        {'password': True},
        keyring_username=keyring_username,
        retry=retry,
    )
