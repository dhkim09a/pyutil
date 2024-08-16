from typing import Callable
import sh
from os import path as _p

from yautil.mount import Archive


YAFFS2_SRC_DIR = _p.join(_p.dirname(__file__), _p.pardir, 'yaffs2utils-0.2.9')


class Yaffs2Archive(Archive):
    mkyaffs2: Callable | None = None
    unyaffs2: Callable | None = None

    def _extract(self, file: str, target_dir: str):
        if not self.unyaffs2:
            sh.make(_cwd=YAFFS2_SRC_DIR) # type: ignore
            self.unyaffs2 = sh.Command('unyaffs2', [YAFFS2_SRC_DIR])

        # --yaffs-ecclayout: https://github.com/djeclipser/yaffs2utils/issues/35#issuecomment-153830017
        self.unyaffs2(file, target_dir, yaffs_ecclayout=True)

    def _archive(self, file: str, source_dir: str):
        if not self.mkyaffs2:
            sh.make(_cwd=YAFFS2_SRC_DIR) # type: ignore
            self.mkyaffs2 = sh.Command('mkyaffs2', [YAFFS2_SRC_DIR])

        self.mkyaffs2(source_dir, file, yaffs_ecclayout=True)

    @classmethod
    def _ismountable(cls, path: str | None = None, file_cmd_out: str | None = None) -> bool:
        if not file_cmd_out:
            return False

        return r'VMS Alpha Executable' in file_cmd_out
