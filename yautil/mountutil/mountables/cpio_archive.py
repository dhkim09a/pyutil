import sh

from yautil.mountutil import Archive


class CpioArchive(Archive):
    def _extract(self, file: str, target_dir: str):
        with open(file, 'r') as f:
            sh.cpio(sh.gzip(d=True, k=True, _in=f), i=True, _cwd=target_dir)

    def _archive(self, file: str, source_dir: str):
        # sh.gzip(sh.mkbootfs(source_dir), _out=file)
        raise NotImplementedError

    @classmethod
    def _ismountable(cls, path: str = None, file_cmd_out: str = None) -> bool:
        if 'gzip compressed data' in file_cmd_out:
            file_cmd_out = sh.file(path, z=True)

        return 'ASCII cpio archive' in file_cmd_out
