from typing import List, Union

try:
    import lief
except ImportError:
    pass


def __validate_import():
    return 'lief' in globals()


def extend_section(elf: lief.ELF.Binary, section: lief.ELF.Section, size: int):
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


class Vernaux:
    vna_hash: int
    vna_flags: int
    vna_other: int
    vna_name: str
    vna_next: object

    elf: lief.ELF.Binary

    def __init__(self, elf: lief.ELF.Binary, vna_name: str, vna_other: int):
        # constants
        self.vna_flags = 0

        # init from params
        self.vna_name = vna_name
        self.vna_other = vna_other
        self.elf = elf

        # just init
        self.vna_hash = 0
        self.vna_next = None

    def __str__(self):
        return 'hash: ' + str(self.vna_hash) \
    + ', flags: ' + str(self.vna_flags) \
               + ', other: ' + str(self.vna_other) \
               + ', name: ' + str(self.vna_name)

    def to_bytes(self):
        b = self.vna_hash.to_bytes(4, byteorder='little', signed=False)
        b += self.vna_flags.to_bytes(2, byteorder='little', signed=False)
        b += self.vna_other.to_bytes(2, byteorder='little', signed=False)
        dynstr_sec: lief.ELF.Section = self.elf.get_section('.dynstr')
        if dynstr_sec.search_all(self.vna_name):
            b += int(dynstr_sec.search(self.vna_name)).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.vna_next:
            b += (16).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        return b


class Verneed:
    vn_version: int
    vn_cnt: int
    vn_file: str
    vn_aux: Union[Vernaux, None]
    vn_next: object

    elf: lief.ELF.Binary

    def __init__(self, elf: lief.ELF.Binary, vn_file: str):
        # constants
        self.vn_version = 1

        # init from params
        self.vn_file = vn_file
        self.elf = elf

        # just init
        self.vn_cnt = 0
        self.vn_aux = None
        self.vn_next = None

    def add_vernaux(self, vernaux: Vernaux):
        self.vn_cnt += 1

        if not (aux := self.vn_aux):
            self.vn_aux = vernaux
            return

        while next_aux := aux.vna_next:
            aux = next_aux

        aux.vna_next = vernaux

    def __str__(self):
        return 'version: ' + str(self.vn_version) \
               + ', cnt: ' + str(self.vn_cnt) \
               + ', file: ' + str(self.vn_file)

    def to_bytes(self):
        b = self.vn_version.to_bytes(2, byteorder='little', signed=False)
        print('vn_cnt: ' + str(self.vn_cnt))
        print('vn_file: ' + str(self.vn_file))
        b += self.vn_cnt.to_bytes(2, byteorder='little', signed=False)
        dynstr_sec: lief.ELF.Section = self.elf.get_section('.dynstr')
        if dynstr_sec.search_all(self.vn_file):
            b += int(dynstr_sec.search(self.vn_file)).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.vn_aux:
            b += (16).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)
        if self.vn_next:
            b += (self.vn_cnt * 16).to_bytes(4, byteorder='little', signed=False)
        else:
            b += (0).to_bytes(4, byteorder='little', signed=False)

        return b


def print_vernauxes(verneed: Verneed):
    if not (aux := verneed.vn_aux):
        return

    print(aux)

    while next_aux := aux.vna_next:
        aux = next_aux
        print(aux)


def print_verneed_recursive(verneed: Verneed):
    v = verneed

    print(v)
    print_vernauxes(v)

    while next_v := v.vn_next:
        v = next_v
        print(v)
        print_vernauxes(v)


def vernauxes_to_bytes(verneed: Verneed):
    if not (aux := verneed.vn_aux):
        return

    b = aux.to_bytes()

    while next_aux := aux.vna_next:
        aux: Vernaux = next_aux
        b += aux.to_bytes()

    return b


def verneed_to_bytes_recursive(verneed: Verneed):
    v = verneed

    b = v.to_bytes()
    b += vernauxes_to_bytes(v)

    while next_v := v.vn_next:
        v: Verneed = next_v
        b += v.to_bytes()
        b += vernauxes_to_bytes(v)

    return b

