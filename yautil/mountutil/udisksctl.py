import getpass
import re
import sys

import keyring as keyring
import sh
from keyring.errors import KeyringLocked


class __UdisksctlAuth:
    SERVICE = 'udisksctl'

    stdout: str = ''

    def udisksctl_auth(self, char, stdin):
        sys.stdout.write(str(char))
        sys.stdout.flush()
        self.stdout += char

        sin = None

        if self.stdout.endswith('): '):
            if not (m := re.search(fr'\s*(?P<no>\d+).*\({getpass.getuser()}\)', self.stdout)):
                print(self.stdout)
                raise Exception(fr'cannot find user {getpass.getuser()} from the list')
            sin = m['no'] + '\n'
        if self.stdout.endswith('Password: '):
            try:
                pw = keyring.get_password(self.SERVICE, getpass.getuser())
                assert pw
            except KeyringLocked:
                pw = getpass.getpass(prompt='')
            except:
                pw = getpass.getpass(prompt='')
                keyring.set_password(self.SERVICE, getpass.getuser(), pw)
            stdin.put(pw + '\n')

            self.stdout = ''

        if sin:
            stdin.put(sin)
            sys.stdout.write(sin)
            sys.stdout.flush()


def udisksctl(*args, _auth: bool = False, **kwargs) -> str:
    if _auth:
        uauth = __UdisksctlAuth()

        sh.udisksctl(*args, **kwargs,
                     _tty_in=True, _tty_out=True, _unify_ttys=True,
                     _out=uauth.udisksctl_auth, _out_bufsize=0)
        return uauth.stdout
    else:
        return str(sh.udisksctl(*args, **kwargs))


def udisksctl_losetup(image) -> str:
    try:
        sout = udisksctl('loop-setup', file=image, _auth=True)
    except Exception:
        raise Exception(fr'failed to open {image}')

    if not (m := re.search(fr'Mapped file {image} as (?P<dev>[^\s]*loop[^\s]*)\.', sout)):
        print(sout)
        raise Exception(fr'failed to map a loop device for {image}')

    print(sout)

    return m['dev']


def udisksctl_mount(loop_dev) -> str:
    try:
        sout = udisksctl('mount', b=loop_dev, o='rw', _auth=True)
    except Exception:
        raise Exception('')

    if not (m := re.search(fr'Mounted {loop_dev} at (?P<dir>[^\s]*)\.', sout)):
        raise Exception(fr'failed to mount {loop_dev}')

    return m['dir']
