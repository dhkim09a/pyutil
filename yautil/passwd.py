from ast import literal_eval
import getpass
import os
from os import PathLike, path as _p
import readline
import sys
import tempfile
import textwrap
from time import sleep
from typing import Any, Callable, Literal, TypeVar

import keyring
import keyring.errors
import keyring.testing
import sh

T = TypeVar('T')


def rlinput(prompt, prefill=''):
    """
    Input function with prefill support.
    
    This function allows the user to edit a pre-filled value instead of starting from an empty input.
    
    Args:
        prompt: The prompt to display to the user.
        prefill: The initial value to pre-fill the input with.
        
    Returns:
        The user's input as a string.
    """
    readline.set_startup_hook(lambda: readline.insert_text(prefill))
    try:
        return input(prompt)
    finally:
        readline.set_startup_hook(None)


def load_secrets(password: str, path: str) -> dict[str, str] | None:
    """
    Load and decrypt secrets from an OpenSSL encrypted file.
    
    This function decrypts a file using OpenSSL AES-256-CBC decryption and parses
    the contents as a Python dictionary.
    
    Args:
        password: The password used to decrypt the file.
        path: The path to the encrypted file.
        
    Returns:
        A dictionary of secrets if successful, None otherwise.
    """
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
    """
    Encrypt and save secrets to a file using OpenSSL.
    
    This function serializes a dictionary of secrets and encrypts it using
    OpenSSL AES-256-CBC encryption, then saves it to the specified path.
    
    Args:
        password: The password used to encrypt the file.
        path: The path where the encrypted file will be saved.
        secrets: A dictionary of secrets to be encrypted and saved.
    """
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
    """
    Internal helper function that handles the core logic for creating objects with secrets.
    
    This function manages the process of:
    1. Loading existing secrets
    2. Prompting user for missing or failed secrets
    3. Calling the constructor with secrets
    4. Saving updated secrets if needed
    5. Retrying the process on failure
    
    Args:
        constructor: A callable that takes a dictionary of secrets and returns an object of type T
                    or None if construction fails.
        secret_desc: A dictionary mapping secret names to boolean values indicating whether each
                    secret is sensitive (True) or non-sensitive (False).
        load_secrets: A callable that returns a dictionary of existing secrets.
        save_secrets: A callable that takes a dictionary of secrets and saves them.
        retry: Number of retry attempts if the constructor returns None.
        
    Returns:
        An object of type T created by the constructor, or None if all retry attempts fail.
    """
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
    """
    Ensure the keyring is unlocked and accessible.
    
    This function checks if the keyring is accessible by trying to get a test password.
    If it's not accessible (InitError is raised), it attempts to unlock the GNOME keyring
    by prompting the user for their password and running the gnome-keyring-daemon.
    """
    try:
        if 'gnome-keyring-daemon' not in str(sh.ps(e=True, f=True)): # type: ignore
            raise keyring.errors.InitError
        keyring.get_password('__test__', '__test__')
    except (keyring.errors.InitError, keyring.errors.KeyringLocked):
        # login_dbus_env = os.environ.copy()
        # login_dbus_env |= {(e := l.strip().split('=', maxsplit=1))[0]: e[1] for l in str(sh.Command('dbus-launch')()).splitlines()}
        # gnome_keyring = sh.Command('gnome-keyring-daemon').bake(_env=login_dbus_env)

        # gnome_keyring = sh.Command('gnome-keyring-daemon')
        # sh.killall('gnome-keyring-daemon', _ok_code=[0,1])
        # passwd = getpass.getpass(f'\rPassword of {getpass.getuser()}: ')
        # gnome_keyring(unlock=True, d=True, r=True, _in=passwd)
        print(textwrap.dedent('''
            Please run the following command in your terminal and try again:
              killall gnome-keyring-daemon
              read -sp "Password: " _tmp_pw && echo && echo $_tmp_pw | gnome-keyring-daemon --unlock --daemonize --replace ; unset _tmp_pw
            Please ensure that "Login" collection is unlocked in `seahorse`.
        '''))
        keyring.get_password('__test__', '__test__')


def create_w_secrets(
    constructor: Callable[[dict[str, str]], T | None],
    servicename: str,
    secret_desc: dict[str, bool],
    retry: int = 2,
    backend: Literal['keyring'] | str = 'keyring',
) -> T | None:
    """
    Create an object using a constructor that requires secret credentials.
    
    This function handles the secure retrieval and storage of secrets needed by the constructor.
    It supports two backends for secret storage: keyring (default) or encrypted file using OpenSSL.
    
    The function will prompt the user for any missing secrets and retry the constructor if it fails,
    up to the specified number of retry attempts.
    
    Args:
        constructor: A callable that takes a dictionary of secrets and returns an object of type T
                    or None if construction fails. The function will retry if None is returned.
        servicename: A string identifier for the service. Used as the service name in keyring or
                    as part of the key for file-based storage.
        secret_desc: A dictionary mapping secret names to boolean values indicating whether each
                    secret is sensitive (True) or non-sensitive (False). Sensitive secrets will be
                    prompted using getpass (no echo), while non-sensitive ones use rlinput (with
                    prefill support).
        retry: Number of retry attempts if the constructor returns None. Defaults to 2.
        backend: The secret storage backend to use. Can be 'keyring' (default) to use the system
                keyring, or a file path string for OpenSSL encrypted file storage.
                
    Returns:
        An object of type T created by the constructor, or None if all retry attempts fail.
        
    Example:
        ``` python
        def connect_to_db(secrets):
            try:
                return DatabaseConnection(secrets['host'], secrets['username'], secrets['password'])
            except ConnectionError:
                return None
                
        db = create_w_secrets(
            constructor=connect_to_db,
            servicename='myapp_db',
            secret_desc={'host': False, 'username': False, 'password': True},
            retry=3
        )
        ```
        
    How it works:
        1. If backend is 'keyring':
           - Loads secrets from system keyring using servicename and secret names
           - Saves secrets to keyring after successful construction
           
        2. If backend is a file path:
           - Uses keyring to store/load a master encryption key (KEK)
           - Uses OpenSSL AES-256-CBC to encrypt/decrypt the secrets file
           - Prompts for master password if needed
    """

    ensure_unlocked()

    if backend == 'keyring':
        try:
            return __create_w_secrets(
                constructor = constructor,
                secret_desc = secret_desc,
                retry = retry,
                load_secrets = lambda: {k: v for k in secret_desc if (v := keyring.get_password(servicename, k))},
                save_secrets = lambda secrets: [keyring.set_password(servicename, k, v) for k, v in secrets.items()],
            )
        except keyring.errors.KeyringLocked as e:
            print(f'error: {e}', file=sys.stderr)
            return

    masterkey_desc: str = f'Password for {backend}'

    def construct_masterkey(secrets: dict[str, str]) -> str | None:
        masterkey = secrets.get(masterkey_desc)
        if not masterkey:
            return
        if _p.exists(backend) and load_secrets(masterkey, backend) is None:
            return
        return masterkey

    masterkey = __create_w_secrets(
        constructor = construct_masterkey,
        secret_desc = {masterkey_desc: True},
        retry = retry,
        load_secrets = lambda: {masterkey_desc: p} if (p := keyring.get_password(servicename, 'KEK')) else {},
        save_secrets = lambda secrets: keyring.set_password(servicename, 'KEK', secrets[masterkey_desc]),
    )

    if not masterkey:
        return

    return __create_w_secrets(
        constructor = constructor,
        secret_desc = secret_desc,
        retry = retry,
        load_secrets = lambda: load_secrets(masterkey, backend) or {},
        save_secrets = lambda secrets: save_secrets(masterkey, backend, secrets),
    )


def create_w_password(
    constructor: Callable[[str], T | None],
    servicename: str,
    retry: int = 2,
) -> T | None:
    """
    Create an object using a constructor that requires a single password.
    
    This is a convenience function that wraps create_w_secrets for the common case
    where only a single password is needed.
    
    Args:
        constructor: A callable that takes a password string and returns an object of type T
                    or None if construction fails.
        servicename: A string identifier for the service, used for keyring storage.
        retry: Number of retry attempts if the constructor returns None. Defaults to 2.
        
    Returns:
        An object of type T created by the constructor, or None if all retry attempts fail.
        
    Example:
        ``` python
        def connect_to_ssh(password):
            try:
                return SSHConnection('user@host.com', password)
            except ConnectionError:
                return None
                
        ssh = create_w_password(
            constructor=connect_to_ssh,
            servicename='ssh_host'
        )
        ```
    """
    def _constructor(secrets: dict[str, str]) -> T | None:
        return constructor(secrets['Password'])
    return create_w_secrets(
        _constructor,
        servicename,
        {'Password': True},
        retry=retry,
    )


# class InvalidSecretsError(Exception):
#     pass


# class InvalidPasswordError(InvalidSecretsError):
#     pass


# class _Attempt:
#     secrets: dict[str, str]
    
#     __servicename: str
#     __secret_desc: dict[str, bool]
#     __retry: int = 2
#     __backend: Literal['keyring'] | str

#     def __init__(
#         self,
#         servicename: str,
#         secret_desc: dict[str, bool],
#         retry: int = 2,
#         backend: Literal['keyring'] | str = 'keyring',
#     ) -> None:
#         self.__servicename = servicename
#         self.__secret_desc = secret_desc
#         self.__retry = retry
#         self.__backend = backend

#     def __enter__(self):
#         return self
    
#     def __exit__(self, exc_type, exc, tb):
#         if exc_type is InvalidSecretsError:
#             return True


# class SecretPrompt:
#     __servicename: str
#     __secret_desc: dict[str, bool]
#     __retry: int = 2
#     __backend: Literal['keyring'] | str

#     def __init__(
#         self,
#         servicename: str,
#         secret_desc: dict[str, bool],
#         retry: int = 2,
#         backend: Literal['keyring'] | str = 'keyring',
#     ) -> None:
#         self.__servicename = servicename
#         self.__secret_desc = secret_desc
#         self.__retry = retry
#         self.__backend = backend

#     def __iter__(self) -> _Attempt:
#         for c in range(self.__retry + 1):
            


# class PasswordPrompt(SecretPrompt):
#     def __init__(
#         self,
#         servicename: str,
#         retry: int = 2,
#     ):
#         super().__init__(
#             servicename=servicename,
#             secret_desc={'Password': True},
#             retry=retry,
#         )

#     def __iter__(self) -> _Attempt:
#         pass
