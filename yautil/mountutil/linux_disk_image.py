import getpass
import re
import sys

import keyring
import sh

from .mountable import Mountable


class UDisksCtlCtx:
    SERVICE = 'udisksctl'

    __dev: str = None
    __mount_point: str = None
    __udisksctl: callable

    _o = ''

    def __udisksctl_auth(self, char, stdin):
        sys.stdout.write(str(char))
        sys.stdout.flush()
        self._o += char

        sin = None

        if self._o.endswith('): '):
            if not (m := re.search(fr'\s*(?P<no>\d+).*\({getpass.getuser()}\)', self._o)):
                print(self._o)
                raise Exception(fr'cannot find user {getpass.getuser()} from the list')
            sin = m['no'] + '\n'
        if self._o.endswith('Password: '):
            if not (pw := keyring.get_password(self.SERVICE, getpass.getuser())):
                pw = getpass.getpass(prompt='')
                keyring.set_password(self.SERVICE, getpass.getuser(), pw)
            stdin.put(pw + '\n')

            self._o = ''

        if sin:
            stdin.put(sin)
            sys.stdout.write(sin)
            sys.stdout.flush()

    def mount(self, image: str):
        try:
            self.__udisksctl('loop-setup', file=image,
                             _tty_in=True, _tty_out=True, _unify_ttys=True,
                             _out=self.__udisksctl_auth, _out_bufsize=0)
            sout = self._o
            self._o = ''
        except Exception:
            raise Exception(fr'failed to open {image}')

        if not (m := re.search(fr'Mapped file {image} as (?P<dev>[^\s]*loop[^\s]*)\.', sout)):
            print(sout)
            raise Exception(fr'failed to map a loop device for {image}')

        self.__dev = m['dev']

        try:
            self.__udisksctl('mount', b=self.__dev, o='rw',
                             _tty_in=True, _unify_ttys=True,
                             _out=self.__udisksctl_auth, _out_bufsize=0)
            sout = self._o
            self._o = ''
        except Exception:
            raise Exception('')

        if not (m := re.search(fr'Mounted {self.__dev} at (?P<dir>[^\s]*)\.', sout)):
            raise Exception(fr'failed to mount {image}')

        self.__mount_point = m['dir']

    def umount(self):
        if self.__mount_point:
            self.__udisksctl('unmount', b=self.__dev)
            self.__mount_point = None

        if self.__dev:
            self.__udisksctl('loop-delete', b=self.__dev)
            self.__dev = None

    def __init__(self):
        self.__udisksctl = sh.udisksctl


class LinuxDiskImage(Mountable):

    def _mount(self, file: str, mode: str, mount_point: str):
        sh.sudo.mount(file, mount_point, _fg=True)

    def _umount(self, mount_point):
        sh.sudo.umount(mount_point, _fg=True)

    @classmethod
    def _pattern(cls) -> str:
        return r'^Linux[^,]*filesystem data'
