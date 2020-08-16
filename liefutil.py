from abc import ABC
from typing import List, Union

try:
    import lief
except ImportError:
    pass


def __validate_import():
    return 'lief' in globals()


def gnu_hash_binutils_bfd_elf(string: str):
    """ toolchain/binutils/binutils-2.27/bfd/elf.c

    /* Standard ELF hash function.  Do not change this function; you will
       cause invalid hash tables to be generated.  */

    unsigned long
    bfd_elf_hash (const char *namearg)
    {
      const unsigned char *name = (const unsigned char *) namearg;
      unsigned long h = 0;
      unsigned long g;
      int ch;

      while ((ch = *name++) != '\0')
        {
          h = (h << 4) + ch;
          if ((g = (h & 0xf0000000)) != 0)
        {
          h ^= g >> 24;
          /* The ELF ABI says `h &= ~g', but this is equivalent in
             this case and on some machines one insn instead of two.  */
          h ^= g;
        }
        }
      return h & 0xffffffff;
    }
    """
    h = 0
    for ch in list(string.encode(encoding='ascii')):
        h = (h << 4) + ch
        if (g := (h & 0xf0000000)) != 0:
            h ^= g >> 24
            h ^= g

    return h & 0xffffffff


def gnu_hash_bionic_linker_linker_sofinfo(string: str):
    """ bionic/linker/linker_soinfo.cpp

    uint32_t calculate_elf_hash(const char* name) {
      const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
      uint32_t h = 0, g;

      while (*name_bytes) {
        h = (h << 4) + *name_bytes++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
      }

      return h;
    }
    """
    h = 0
    for ch in list(string.encode(encoding='ascii')):
        h = ((h << 4) + ch) & 0xffffffff
        g = h & 0xf0000000
        h ^= g
        h ^= g >> 24

    return h


def gnu_hash(string: str):
    return gnu_hash_bionic_linker_linker_sofinfo(string)
    # return gnu_hash_binutils_bfd_elf(string)


def extend_section(elf: lief.ELF.Binary, section: Union[lief.ELF.Section, str], size: int):
    if size <= 0:
        return

    if isinstance(section, str):
        section: lief.ELF.Section = elf.get_section(section)

    elf.extend(section, size)

    for ent in elf.dynamic_entries:
        # bionic/libc/include/elf.h
        DT_LOOS = 0x6000000d
        DT_ANDROID_REL = DT_LOOS + 2
        DT_ANDROID_RELSZ = DT_LOOS + 3
        DT_ANDROID_RELA = DT_LOOS + 4
        DT_ANDROID_RELASZ = DT_LOOS + 5
        if ((int(ent.tag) == DT_ANDROID_REL) or (int(ent.tag) == DT_ANDROID_RELA)) \
                and ent.value > section.file_offset:
            ent.value += size


def get_section_content(elf: lief.ELF.Binary, section: Union[lief.ELF.Section, str]) -> bytes:
    if isinstance(section, str):
        section: lief.ELF.Section = elf.get_section(section)

    c: List = section.content
    return bytes(c)


def set_section_content(elf: lief.ELF.Binary, section: Union[lief.ELF.Section, str], b: bytes):
    if isinstance(section, str):
        section: lief.ELF.Section = elf.get_section(section)

    c: List = section.content
    prev_len = len(c)

    extend_section(elf, section, len(b) - prev_len)
    section.content = list(b)


def append_strtab(elf: lief.ELF.Binary, section: Union[lief.ELF.Section, str], string: str):
    content = get_section_content(elf, section)
    content += str(string + '\0').encode('ascii')
    set_section_content(elf, section, content)


class ModificationContext:
    elf: lief.ELF.Binary

    def __init__(self, elf: lief.ELF.Binary):
        self.elf = elf


class Version:
    next: object

    def __init__(self):
        self.next = None

    @classmethod
    def __len__(cls) -> int:
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, elf: lief.ELF.Binary, b: bytes):
        raise NotImplementedError

    def to_bytes(self, elf: lief.ELF.Binary):
        raise NotImplementedError


class VersionList:
    head: Union[Version, None]
    next: Union[Version, None]
    size: int

    def __init__(self):
        self.head = None
        self.next = None
        self.size = 0

    def __iter__(self):
        self.next = self.head
        return self

    def __next__(self) -> Version:
        if self.next:
            cur = self.next
            if self.next.next:
                assert isinstance(self.next.next, Version)
                self.next = self.next.next
            else:
                self.next = None
            return cur
        else:
            raise StopIteration

    def __len__(self):
        return self.size

    def append(self, version: Version):
        self.size += 1

        if not (v := self.head):
            self.head = version
            return

        while next_v := v.next:
            v = next_v

        v.next = version


class SuperVersion(Version, ABC):
    cnt: int
    aux: Union[Version, None]

    veraux_list: Union[VersionList, None]

    def __init__(self):
        super().__init__()
        self.veraux_list = None

    def add_veraux(self, veraux: Version):
        if not self.veraux_list:
            self.veraux_list = VersionList()
            self.aux = veraux

        self.veraux_list.append(veraux)

        if self.cnt < len(self.veraux_list):
            self.cnt = len(self.veraux_list)


class Verdaux(Version):
    name: str
    next: Union[Version, None]

    def __init__(self, vda_name: str):
        super().__init__()
        self.name = vda_name

    @classmethod
    def __len__(cls) -> int:
        return 8

    @classmethod
    def from_bytes(cls, elf: lief.ELF.Binary, b: bytes):
        assert len(b) == Verdaux.__len__()

        vda_name = int.from_bytes(b[0:4], byteorder='little', signed=False)
        vda_next = int.from_bytes(b[4:8], byteorder='little', signed=False)

        if vda_next != 0 and vda_next != Verdaux.__len__():
            print('error: weird vn_aux offset')

        c = get_section_content(elf, '.dynstr')

        end = c.find(b'\0', vda_name)
        name = c[vda_name:end].decode(encoding='ascii')

        verdaux = Verdaux(name)

        return verdaux

    def to_bytes(self, elf: lief.ELF.Binary):
        dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        if dynstr_sec.search_all(self.name):
            b = int(dynstr_sec.search(self.name)).to_bytes(4, byteorder='little', signed=False)
        else:
            b = (0).to_bytes(4, byteorder='little', signed=False)
        if self.next:
            b += (Verdaux.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        assert len(b) == Verdaux.__len__()

        return b

    def __str__(self):
        return '(verdaux) name: ' + str(self.name) \
               + ' (gnu hash: ' + hex(gnu_hash(self.name)) + ')'


class Verdef(SuperVersion):
    version: int
    flags: int
    ndx: int
    cnt: int
    hash: int
    aux: Union[Verdaux, None]
    next: Union[Version, None]

    @classmethod
    def __len__(cls) -> int:
        return 20

    @classmethod
    def from_bytes(cls, elf: lief.ELF.Binary, b: bytes):
        assert len(b) == Verdef.__len__()

        vd_version = int.from_bytes(b[0:2], byteorder='little', signed=False)
        vd_flags = int.from_bytes(b[2:4], byteorder='little', signed=False)
        vd_ndx = int.from_bytes(b[4:6], byteorder='little', signed=False)
        vd_cnt = int.from_bytes(b[6:8], byteorder='little', signed=False)
        vd_hash = int.from_bytes(b[8:12], byteorder='little', signed=False)
        vd_aux = int.from_bytes(b[12:16], byteorder='little', signed=False)
        vd_next = int.from_bytes(b[16:20], byteorder='little', signed=False)

        if vd_version != 1:
            print('error: vd_version must be 1')
        if vd_aux != 0 and vd_aux != Verdef.__len__():
            print('error: weird vd_aux offset')

        verdef = Verdef()

        verdef.version = vd_version
        verdef.flags = vd_flags
        verdef.ndx = vd_ndx
        verdef.cnt = vd_cnt
        verdef.hash = vd_hash

        return verdef

    def to_bytes(self, elf: lief.ELF.Binary):
        b = self.version.to_bytes(2, byteorder='little', signed=False)
        b += self.flags.to_bytes(2, byteorder='little', signed=False)
        b += self.ndx.to_bytes(2, byteorder='little', signed=False)
        b += self.cnt.to_bytes(2, byteorder='little', signed=False)
        b += self.hash.to_bytes(4, byteorder='little', signed=False)
        if self.aux:
            b += (Verdef.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.next:
            b += (Verdef.__len__() + self.cnt * Verdaux.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        assert len(b) == Verdef.__len__()

        return b

    def __str__(self):
        return '(verdef) version: ' + str(self.version) \
               + ', flags: ' + str(self.flags) \
               + ', ndx: ' + str(self.ndx) \
               + ', cnt: ' + str(self.cnt) \
               + ', hash: ' + hex(self.hash)


class Vernaux(Version):
    hash: int
    flags: int
    other: int
    name: str
    next: Union[Version, None]

    def __init__(self, vna_name: str, vna_other: int):
        super().__init__()

        # constants
        self.flags = 0

        # init from params
        self.name = vna_name
        self.other = vna_other
        self.hash = gnu_hash(vna_name)

    @classmethod
    def __len__(cls) -> int:
        return 16

    @classmethod
    def from_bytes(cls, elf: lief.ELF.Binary, b: bytes):
        assert len(b) == Vernaux.__len__()

        vna_hash = int.from_bytes(b[0:4], byteorder='little', signed=False)
        vna_flags = int.from_bytes(b[4:6], byteorder='little', signed=False)
        vna_other = int.from_bytes(b[6:8], byteorder='little', signed=False)
        vna_name = int.from_bytes(b[8:12], byteorder='little', signed=False)
        vna_next = int.from_bytes(b[12:16], byteorder='little', signed=False)

        if vna_next != 0 and vna_next != Vernaux.__len__():
            print('error: weird vn_aux offset')

        dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        c = bytes(dynstr_sec.content)

        end = c.find(b'\0', vna_name)
        name = c[vna_name:end].decode(encoding='ascii')

        vernaux = Vernaux(name, vna_other)

        vernaux.hash = vna_hash
        vernaux.flags = vna_flags

        return vernaux

    def __str__(self):
        return '(vernaux) hash: ' + hex(self.hash) \
               + ', flags: ' + str(self.flags) \
               + ', other: ' + str(self.other) \
               + ', name: ' + str(self.name) \
               + ' (gnu hash: ' + hex(gnu_hash(self.name)) + ')'

    def to_bytes(self, elf: lief.ELF.Binary):
        b = self.hash.to_bytes(4, byteorder='little', signed=False)
        b += self.flags.to_bytes(2, byteorder='little', signed=False)
        b += self.other.to_bytes(2, byteorder='little', signed=False)
        dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        if dynstr_sec.search_all(self.name):
            b += int(dynstr_sec.search(self.name)).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.next:
            b += (Vernaux.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        assert len(b) == Vernaux.__len__()

        return b


class Verneed(SuperVersion):
    version: int
    cnt: int
    file: str
    aux: Union[Vernaux, None]
    next: Union[Version, None]

    @classmethod
    def __len__(cls) -> int:
        return 16

    @classmethod
    def from_bytes(cls, elf: lief.ELF.Binary, b: bytes):
        assert len(b) == Verneed.__len__()

        vn_version = int.from_bytes(b[0:2], byteorder='little', signed=False)
        vn_cnt = int.from_bytes(b[2:4], byteorder='little', signed=False)
        vn_file = int.from_bytes(b[4:8], byteorder='little', signed=False)
        vn_aux = int.from_bytes(b[8:12], byteorder='little', signed=False)
        vn_next = int.from_bytes(b[12:16], byteorder='little', signed=False)

        if vn_version != 1:
            print('error: vn_version must be 1')
        if vn_aux != 0 and vn_aux != Verneed.__len__():
            print('error: weird vn_aux offset')

        c = get_section_content(elf, '.dynstr')

        end = c.find(b'\0', vn_file)
        file = c[vn_file:end].decode(encoding='ascii')

        verneed = Verneed(file)

        verneed.version = vn_version
        verneed.cnt = vn_cnt

        return verneed

    def __init__(self, vn_file: str):
        super().__init__()

        # constants
        self.version = 1

        # init from params
        self.file = vn_file

        # just init
        self.cnt = 0
        self.aux = None

    def __str__(self):
        return '(verneed) version: ' + str(self.version) \
               + ', cnt: ' + str(self.cnt) \
               + ', file: ' + str(self.file)

    def to_bytes(self, elf: lief.ELF.Binary):
        b = self.version.to_bytes(2, byteorder='little', signed=False)
        b += self.cnt.to_bytes(2, byteorder='little', signed=False)
        dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        if dynstr_sec.search_all(self.file):
            b += int(dynstr_sec.search(self.file)).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.aux:
            b += (Verneed.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.next:
            b += (Verneed.__len__() + self.cnt * Vernaux.__len__()).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        assert len(b) == Verneed.__len__()

        return b


class SymbolVersionContext(ModificationContext):
    verdef_list: Union[VersionList, None]
    verneed_list: Union[VersionList, None]

    def __init__(self, elf: lief.ELF.Binary):
        super().__init__(elf)

        self.verneed_list = VersionList()

    def __parse_version_definition(self):
        self.verdef_list = VersionList()

        c = get_section_content(self.elf, '.gnu.version_d')

        while c:
            verdef_bytes = c[0:Verdef.__len__()]
            c = c[Verdef.__len__():]
            verdef = Verdef.from_bytes(self.elf, verdef_bytes)
            for i in range(verdef.cnt):
                verdaux_bytes = c[0:Verdaux.__len__()]
                c = c[Verdaux.__len__():]
                verdaux = Verdaux.from_bytes(self.elf, verdaux_bytes)
                verdef.add_veraux(verdaux)
            self.verdef_list.append(verdef)

    def __parse_version_requirement(self):
        self.verneed_list = VersionList()

        c = get_section_content(self.elf, '.gnu.version_r')

        while c:
            verneed_bytes = c[0:Verneed.__len__()]
            c = c[Verneed.__len__():]
            verneed = Verneed.from_bytes(self.elf, verneed_bytes)
            for i in range(verneed.cnt):
                vernaux_bytes = c[0:Vernaux.__len__()]
                c = c[Vernaux.__len__():]
                vernaux = Vernaux.from_bytes(self.elf, vernaux_bytes)
                verneed.add_veraux(vernaux)
            self.verneed_list.append(verneed)

    def parse(self):
        self.__parse_version_definition()
        self.__parse_version_requirement()

    def add_version_requirement(self, vn_file: str, vna_name: str, vna_other: int):
        if matches := [e for e in filter(lambda e: e.file == vn_file, self.verneed_list)]:
            assert len(matches) == 1
            verneed: Verneed = matches[0]
            if matches := [e for e in filter(lambda e: e.name == vna_name, verneed.veraux_list)]:
                assert len(matches) == 1
            else:
                vernaux = Vernaux(vna_name, vna_other)
                verneed.add_veraux(vernaux)
        else:
            verneed = Verneed(vn_file)
            vernaux = Vernaux(vna_name, vna_other)
            verneed.add_veraux(vernaux)
            self.verneed_list.append(verneed)

    def get_version_definition(self) -> bytes:
        b = bytes()
        for verdef in self.verdef_list:
            verdef: Verdef
            b += verdef.to_bytes(self.elf)
            for verdaux in verdef.veraux_list:
                b += verdaux.to_bytes(self.elf)
        return b

    def get_version_requirement(self) -> bytes:
        b = bytes()
        for verneed in self.verneed_list:
            verneed: Verneed
            b += verneed.to_bytes(self.elf)
            for vernaux in verneed.veraux_list:
                b += vernaux.to_bytes(self.elf)
        return b

    def __commit_version_definition(self):
        verdefnum: lief.ELF.DynamicEntryLibrary = self.elf.get(lief.ELF.DYNAMIC_TAGS.VERDEFNUM)
        verdefnum.value = len(self.verdef_list)
        set_section_content(self.elf, '.gnu.version_d', self.get_version_definition())

    def __commit_version_requirement(self):
        verneednum: lief.ELF.DynamicEntryLibrary = self.elf.get(lief.ELF.DYNAMIC_TAGS.VERNEEDNUM)
        verneednum.value = len(self.verneed_list)
        set_section_content(self.elf, '.gnu.version_r', self.get_version_requirement())

    def commit(self):
        self.__commit_version_definition()
        self.__commit_version_requirement()

    def __str_version_definition(self):
        string = 'Section .gnu.version_d\n'
        for verdef in self.verdef_list:
            verdef: Verneed
            string += str(verdef) + '\n'
            for verdaux in verdef.veraux_list:
                string += str(verdaux) + '\n'
        return string

    def __str_version_requirement(self):
        string = 'Section .gnu.version_r\n'
        for verneed in self.verneed_list:
            verneed: Verneed
            string += str(verneed) + '\n'
            for vernaux in verneed.veraux_list:
                string += str(vernaux) + '\n'
        return string

    def __str__(self):
        string = ''
        string += self.__str_version_definition()
        string += self.__str_version_requirement()
        return string
