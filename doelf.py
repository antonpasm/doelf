#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#  doelf
#  30/10/2020
#
#  PASm
#
#  based on the sym2elf by  Daniel García and Jesús Olmos
#  ELF parser - based on the lib of ROPgadget tool by Jonathan Salwan
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.
#

PLUG_NAME = "doelf"

ELF_E_MACHINE = 0

WRITE_PROGRAM_HEADERS = True    # ELF will contain program headers
WRITE_SYMBOLS = True            # ELF will contain Symbols information

ADD_COMMENT = False             # todo. Symbols information will contain IDA comments

import os
import sys
from ctypes import *

USE_IDA = False
try:
    import idaapi
    USE_IDA = True
except:
        print("ERROR: The plugin must be run in IDA")
        sys.exit(0)

if USE_IDA:
    from idc import *
    from idaapi import *
    from idautils import *

SHN_UNDEF = 0

# ELF32_ST_BIND
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_NUM = 3

# ELF32_ST_TYPE
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLC = 6
STT_NUM = 7


def ELF_ST_INFO(b, t):
    return (b << 4) | (t & 0xF)


class SHTypes:
    SHT_NULL      = 0
    SHT_PROGBITS  = 1
    SHT_SYMTAB    = 2
    SHT_STRTAB    = 3
    SHT_RELA      = 4
    SHT_HASH      = 5
    SHT_DYNAMIC   = 6
    SHT_NOTE      = 7
    SHT_NOBITS    = 8
    SHT_REL       = 9
    SHT_SHLIB     = 10
    SHT_DYNSYM    = 11
    SHT_NUM       = 12
    SHT_LOPROC    = 0x70000000
    SHT_HIPROC    = 0x7fffffff
    SHT_LOUSER    = 0x80000000
    SHT_HIUSER    = 0xffffffff


class SHFlags:
    SHF_NONE      = 0
    SHF_WRITE     = 1
    SHF_ALLOC     = 2
    SHF_EXECINSTR = 4


class PHTypes:
    PT_NULL       = 0
    PT_LOAD       = 1


class PHFlags:
    PF_NONE       = 0
    PF_EXEC       = 1
    PF_WRITE      = 2
    PF_READ       = 4


class ELFFlags:
    EI_MAG0     = 0
    EI_MAG1     = 1
    EI_MAG2     = 2
    EI_MAG3     = 3
    EI_CLASS    = 4
    EI_DATA     = 5
    EI_VERSION  = 6
    EI_OSABI    = 7
    EI_PAD      = 8
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    E_CURRENT  = 0x01


class SymFlags:
    STB_LOCAL   = 0
    STB_GLOBAL  = 1
    STB_WEAK    = 2
    STT_NOTYPE  = 0
    STT_OBJECT  = 1
    STT_FUNC    = 2
    STT_SECTION = 3
    STT_FILE    = 4
    STT_COMMON  = 5
    STT_TLS     = 6


class CProgram(object):
    def __init__(self):
        super(CProgram, self).__init__()
        self.section = None


class CSection(object):
    def __init__(self):
        super(CSection, self).__init__()
        self._bin = b''
        self.str_name = None

    @property
    def bin(self):
        return self._bin

    @bin.setter
    def bin(self, value):
        self._bin = value
        self.sh_size = len(value)

    @property
    def raw(self):
        align = self.sh_addralign
        if align:
            return self._bin + b'\x00' * ((align-len(self._bin)) % align)
        else:
            return self._bin


class CSymbol(object):
    def __init__(self):
        super(CSymbol, self).__init__()
        self.str_name = None


class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]


class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]


class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]


class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]


class Elf32_Phdr_LSB(CProgram, LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
               ]


class Elf64_Phdr_LSB(CProgram, LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]


class Elf32_Phdr_MSB(CProgram, BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]


class Elf64_Phdr_MSB(CProgram, BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]


class Elf32_Shdr_LSB(CSection, LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]


class Elf64_Shdr_LSB(CSection, LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]


class Elf32_Shdr_MSB(CSection, BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]


class Elf64_Shdr_MSB(CSection, BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]


class Elf32_Sym_LSB(CSymbol, LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]


class Elf64_Sym_LSB(CSymbol, LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]


class Elf32_Sym_MSB(CSymbol, BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]


class Elf64_Sym_MSB(CSymbol, BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]


class Strtab():
    def __init__(self):
        self.offsets = []
        self._raw = bytearray(b'\x00')

    def append(self, name):
        if name is not None:
            o = len(self._raw)
            self._raw.extend(name.encode('ascii') + b'\x00')
            return o
        else:
            return SHN_UNDEF

    def raw(self):
        # add to the end a null string
        return self._raw + b'\x00'


class ELF(object):
    def __init__(self, is32, islsb):
        self.is32 = is32
        self.islsb = islsb
        self.binary = bytearray()
        if self.is32:
            if self.islsb:
                self._Elf_Ehdr = Elf32_Ehdr_LSB
                self._Elf_Phdr = Elf32_Phdr_LSB
                self._Elf_Shdr = Elf32_Shdr_LSB
                self._Elf_Sym = Elf32_Sym_LSB
            else:
                self._Elf_Ehdr = Elf32_Ehdr_MSB
                self._Elf_Phdr = Elf32_Phdr_MSB
                self._Elf_Shdr = Elf32_Shdr_MSB
                self._Elf_Sym = Elf32_Sym_MSB
        else:
            if self.islsb:
                self._Elf_Ehdr = Elf64_Ehdr_LSB
                self._Elf_Phdr = Elf64_Phdr_LSB
                self._Elf_Shdr = Elf64_Shdr_LSB
                self._Elf_Sym = Elf64_Sym_LSB
            else:
                self._Elf_Ehdr = Elf64_Ehdr_MSB
                self._Elf_Phdr = Elf64_Phdr_MSB
                self._Elf_Shdr = Elf64_Shdr_MSB
                self._Elf_Sym = Elf64_Sym_MSB
        self.ElfHeader = self._Elf_Ehdr()

        self.ElfHeader.e_ident[ELFFlags.EI_MAG0:ELFFlags.EI_MAG3+1] = bytearray(b'\x7FELF')
        self.ElfHeader.e_ident[ELFFlags.EI_CLASS] = ELFFlags.ELFCLASS32 if self.is32 else ELFFlags.ELFCLASS64
        self.ElfHeader.e_ident[ELFFlags.EI_DATA] = ELFFlags.ELFDATA2LSB if self.islsb else ELFFlags.ELFDATA2MSB
        self.ElfHeader.e_ident[ELFFlags.EI_VERSION] = ELFFlags.E_CURRENT
        self.ElfHeader.e_type = 0x02        # ET_EXEC
        self.ElfHeader.e_machine = ELF_E_MACHINE
        self.ElfHeader.e_version = 0x01     # EV_CURRENT
        self.ElfHeader.e_entry = 0          # START_ADDRESS
        # self.ElfHeader.e_phoff = 0
        # self.ElfHeader.e_shoff = 0
        self.ElfHeader.e_flags = 0
        self.ElfHeader.e_ehsize = sizeof(self.ElfHeader)
        self.ElfHeader.e_phentsize = 0
        # self.ElfHeader.e_phnum = 0
        self.ElfHeader.e_shentsize = 0
        # self.ElfHeader.e_shnum = 0
        self.ElfHeader.e_shstrndx = 0

        self.shstr = None

        self.shdr_l = []
        self.phdr_l = []

    def get_section_id(self, section):
        return self.shdr_l.index(section)

    def find_section_id(self, name):
        for idx, sh in enumerate(self.shdr_l):
            if sh.str_name == name:
                return idx
        return None

    def append_program_header(self, p_type=PHTypes.PT_LOAD, p_vaddr=0, p_paddr=0, p_flags=PHFlags.PF_READ, p_align=0, section=None):
        p = self._Elf_Phdr()
        p.p_type = p_type
        # p.p_offset = p_offset
        p.p_vaddr = p_vaddr
        p.p_paddr = p_paddr
        # p.p_filesz = p_filesz
        # p.p_memsz = p_memsz
        p.p_flags = p_flags
        p.p_align = p_align
        # p.bin = bin
        p.section = section
        self.phdr_l.append(p)
        return p

    def append_section_header(self, name=None, sh_type=SHTypes.SHT_NULL, sh_flags=0, sh_addr=0, sh_size=0, sh_link=0, sh_info=0, sh_addralign=0, sh_entsize=0, bin=None):
        s = self._Elf_Shdr()
        if bin is None:
            s.sh_size = sh_size
        else:
            s.bin = bin
        if isinstance(name, int):
            s.sh_name = name
        s.sh_type = sh_type
        s.sh_flags = sh_flags
        s.sh_addr = sh_addr
        # s.sh_offset = sh_offset
        s.sh_link = sh_link
        s.sh_info = sh_info
        s.sh_addralign = sh_addralign
        s.sh_entsize = sh_entsize
        s.str_name = name
        self.shdr_l.append(s)
        return s

    def append_section_null(self):
        return self.append_section_header()

    def append_section_strtab(self, name='.shstrtab', sh_addralign=4):
        sect = self.append_section_header(name, SHTypes.SHT_STRTAB, sh_addralign=sh_addralign)
        self.shstr = sect
        return sect

    def create_elf_symbol(self, name=None, st_value=0, st_size=0, st_info=0, st_other=0, sh_name=None):
        if sh_name is None:
            st_shndx = 0
        else:
            st_shndx = self.find_section_id(sh_name)
            if not st_shndx:
                log("ERROR: Section ID for '%s' not found" % sh_name)
                return None

        s = self._Elf_Sym()
        if isinstance(name, int):
            s.st_name = name
        s.st_value = st_value
        s.st_size = st_size
        s.st_info = st_info
        s.st_other = st_other
        s.st_shndx =st_shndx
        s.str_name = name
        return s

    def build(self):
        # HEADER
        # PROGRAM HEADERS
        # SECTION HEADERS
        # sections binary data
        # EOF

        self.binary = bytearray()

        # build shstrtab
        if self.shstr:
            i = self.get_section_id(self.shstr)
            self.ElfHeader.e_shstrndx = i

            strtab = Strtab()
            for s in self.shdr_l:
                s.sh_name = strtab.append(s.str_name)
            self.shstr.bin = strtab.raw()


        # fix header
        pdhr_num = len(self.phdr_l)
        self.ElfHeader.e_phnum = pdhr_num
        if pdhr_num:
            self.ElfHeader.e_phentsize = sizeof(self._Elf_Phdr)

        shdr_num = len(self.shdr_l)
        self.ElfHeader.e_shnum = shdr_num
        if shdr_num:
            self.ElfHeader.e_shentsize = sizeof(self._Elf_Shdr)

        ph_offset = sizeof(self.ElfHeader)
        sh_offset = ph_offset + pdhr_num*self.ElfHeader.e_phentsize
        data_offset = sh_offset + shdr_num*self.ElfHeader.e_shentsize

        self.ElfHeader.e_phoff = ph_offset
        self.ElfHeader.e_shoff = sh_offset


        # set offsets in sections
        o = data_offset
        for s in self.shdr_l:
            s.sh_offset = o
            o += len(s.raw)

        # set offset in programs
        for p in self.phdr_l:
            if p.section:
                p.p_offset = p.section.sh_offset
                p.p_filesz = p.section.sh_size
                p.p_memsz = p.section.sh_size
                p.p_vaddr = p.section.sh_addr
                p.p_paddr = p.section.sh_addr

        # Write Header
        b = bytearray(self.ElfHeader)
        self.binary.extend(b)

        # Write Program headers
        self.binary.extend(concatbytes(self.phdr_l))

        # Write Section headers
        self.binary.extend(concatbytes(self.shdr_l))

        # Write binary of sections
        for s in self.shdr_l:
            self.binary.extend(s.raw)

    def save(self, output):
        with open(output, 'wb') as f:
            f.write(self.binary)


class Segment:
    def __init__(self, name, address, size, bin, type, align, flags, p_flags=0):
        self.name = name
        self.address = address
        self.size = size
        self.bin = bin
        self.type = type
        self.align = align
        self.flags = flags
        self.p_flags = p_flags


class Symbol:
    def __init__(self, name, bind, type, value, size, shname, shndx=-1):
        self.name   = name
        self.bind   = bind
        self.type   = type
        self.value  = value
        self.size   = size
        self.shname = shname
        self.shndx  = shndx


def log(msg=''):
    print("[%s] %s" % (PLUG_NAME, msg))


def concatbytes(l):
    return bytearray().join([bytearray(i) for i in l])


def write_symbols(output_file, is32, islsb, ep, segments, symbols):
    try:
        if len(segments) < 1:
            log("No segments to export")
            return

        if len(symbols) < 1:
            log("No symbols to export")

        log("Building ELF...")

        elf = ELF(is32=is32, islsb=islsb)
        elf.ElfHeader.e_entry = ep

        log("EI_CLASS:   %s" % 'ELFCLASS32' if elf.ElfHeader.e_ident[ELFFlags.EI_CLASS] else 'ELFCLASS64')
        log("EI_DATA:    %s" % 'ELFDATA2LSB' if elf.ElfHeader.e_ident[ELFFlags.EI_DATA] else 'ELFDATA2MSB')
        log("e_machine:  %d" % elf.ElfHeader.e_machine)
        log("Entry point: 0x%X" % ep)

        elf.append_section_null()       # empty section
        elf.append_section_strtab()     # strtab section names

        for seg in segments:
            sec = elf.append_section_header(seg.name, sh_type=seg.type, sh_flags=seg.flags, sh_addr=seg.address, sh_size=seg.size, sh_addralign=seg.align, bin=seg.bin)
            if WRITE_PROGRAM_HEADERS:
                if seg.type == SHTypes.SHT_PROGBITS and seg.bin:
                    elf.append_program_header(p_flags=seg.p_flags, p_align=seg.align, section=sec)

        if WRITE_SYMBOLS:
            elf_symbols = []
            # Add Separator
            elf_symbols.append(elf.create_elf_symbol())

            # 'sort' symbols. Local first
            for sym in symbols:
                if sym.bind == STB_LOCAL:
                    st_info = ELF_ST_INFO(sym.bind, sym.type)
                    elf_symbol = elf.create_elf_symbol(sym.name, sym.value, sym.size, st_info, 0, sym.shname)
                    if elf_symbol:
                        elf_symbols.append(elf_symbol)

            local_cnt = len(elf_symbols)    # nums of LOCAL symbols + 1 (separator)

            # Not Local next
            for sym in symbols:
                if sym.bind != STB_LOCAL:
                    st_info = ELF_ST_INFO(sym.bind, sym.type)
                    elf_symbol = elf.create_elf_symbol(sym.name, sym.value, sym.size, st_info, 0, sym.shname)
                    if elf_symbol:
                        elf_symbols.append(elf_symbol)

            strtab = Strtab()
            for s in elf_symbols:
                s.st_name = strtab.append(s.str_name)

            strtab = elf.append_section_header('.strtab', sh_type=SHTypes.SHT_STRTAB, sh_addralign=4, bin=strtab.raw())
            symtab = elf.append_section_header('.symtab', sh_type=SHTypes.SHT_SYMTAB,
                                               sh_link=elf.get_section_id(strtab),
                                               sh_info=local_cnt,
                                               sh_addralign=4,
                                               sh_entsize=sizeof(elf._Elf_Sym),
                                               bin=concatbytes(elf_symbols))

        elf.build()
        elf.save(output_file)
        log("ELF saved to: %s" % output_file)

    except:
        log(traceback.format_exc())


# Get is 32
def get_ida_is32():
    return not idaapi.cvar.inf.is_64bit()      # not shure


# Get LSB
def get_ida_islsb():
    return not idaapi.cvar.inf.mf   # not shure


# Get EP
def get_ida_ep():
    i = GetEntryPointQty()
    if i:
        return GetEntryOrdinal(0)
    else:
        return get_imagebase()


# Get Segments
def get_ida_segments():
    segments = []
    for s in Segments():
        address = SegStart(s)
        end = SegEnd(s)
        size = end-address
        name = SegName(s)
        align = GetSegmentAttr(s, SEGATTR_ALIGN)    # not sure
        permission = GetSegmentAttr(s, SEGATTR_PERM)
        bin = GetManyBytes(address, size)

        type = SHTypes.SHT_PROGBITS if bin else SHTypes.SHT_NOBITS
        flags = SHFlags.SHF_ALLOC
        if permission & SEGPERM_EXEC:
            flags |= SHFlags.SHF_EXECINSTR
        if permission & SEGPERM_WRITE:
            flags |= SHFlags.SHF_WRITE
        # if permission & SEGPERM_READ:
        #     flags |= SHFlags.SHF_ALLOC
        p_flags = permission
        segments.append(Segment(name, address, size, bin, type, align, flags, p_flags))
    return segments


# Get Symbols
def ida_fcn_filter(func_ea):
    if SegName(func_ea) not in ("extern", ".plt"):
        return True


def get_ida_symbols_simple():
    symbols = []
    for f in filter(ida_fcn_filter, Functions()):
        func     = get_func(f)
        seg_name = SegName(f)
        fn_name = GetFunctionName(f)
        print(fn_name, hex(int(func.startEA)))
        symbols.append(Symbol(fn_name, STB_GLOBAL, STT_FUNC, int(func.startEA), int(func.size()), seg_name))
    return symbols


def get_ida_symbols():
    symbols = []
    startEA = cvar.inf.minEA
    endEA = cvar.inf.maxEA
    while (startEA < endEA):
        f = get_flags_novalue(startEA)

        # todo: how to determine that the name is local?
        #  inverse function of set_name ?
        #  how get flags SN_ from EA?

        if isFunc(f):
            name = get_func_name(startEA)
            func = get_func(startEA)
            start = func.startEA
            size = func.endEA - start
            segname = SegName(startEA)
            # Add function name
            symbols.append(Symbol(name, STB_GLOBAL, STT_FUNC, start, size, segname))

        else:
            if f & FF_NAME:
                name = get_true_name(startEA)
                # name = get_short_name(startEA)
                bind = STB_GLOBAL
                if not name:
                    name = get_name(startEA, startEA)   # not sure
                    bind = STB_LOCAL
                start = startEA
                size = 0
                segname = SegName(startEA)
                # Add global name
                symbols.append(Symbol(name, bind, STT_OBJECT, start, size, segname))

            if f & FF_LABL:
                name = get_true_name(startEA)
                # name = get_short_name(startEA)
                name_l = ''
                start = startEA
                size = 0
                segname = SegName(startEA)
                # Add label
                symbols.append(Symbol(name, STB_GLOBAL, STT_OBJECT, start, size, segname))
                if f & FF_NAME:
                    # Имя уже есть, пробуем получить label
                    func = get_func(startEA)
                    if func:
                        name_l = get_name(func.startEA, startEA)
                        if name_l and name_l != name:
                            # Add local(?) label
                            symbols.append(Symbol(name_l, STB_LOCAL, STT_OBJECT, start, size, segname))

            if ADD_COMMENT and (f & FF_LINE):
                cmt = []
                i = 0
                while (True):
                    l = LineA(startEA, i)
                    if not l:
                        break
                    cmt.append(l)
                    i += 1
                name_a = 'r\n'.join(cmt)
                cmt = []
                i = 0
                while (True):
                    l = LineB(startEA, i)
                    if not l:
                        break
                    cmt.append(l)
                    i += 1
                name_p = 'r\n'.join(cmt)
                start = startEA
                size = 0
                segname = SegName(startEA)
                # Stub. Todo
                if name_a:
                    symbols.append(Symbol(name_a, STB_LOCAL, STT_OBJECT, start, size, segname))
                if name_p:
                    symbols.append(Symbol(name_p, STB_LOCAL, STT_OBJECT, next_not_tail(start), size, segname))

            if ADD_COMMENT and (f & FF_COMM):
                name_r = get_cmt(startEA, True)
                name_n = get_cmt(startEA, False)
                start = startEA
                size = 0
                segname = SegName(startEA)
                # Stub. Todo
                if name_r:
                    symbols.append(Symbol(name_r, STB_LOCAL, STT_OBJECT, start, size, segname))
                if name_n:
                    symbols.append(Symbol(name_n, STB_LOCAL, STT_OBJECT, start, size, segname))

        startEA = next_not_tail(startEA)
    return symbols


class DoElf(Form):
    def __init__(self):
        Form.__init__(self, ("DoELF\n"
                             "<Output ELF ~f~ile:{txtFile}>\n"
                             "\n"
                             ), {
                          'txtFile': Form.FileInput(save=True)
                      })

    def Show(self):
        self.Compile()
        return self.Execute()


class DoElf_t(plugin_t):
    flags = PLUGIN_UNL
    comment = "Produce ELF file with symbolic information"
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = ""

    def init(self):
        return PLUGIN_OK

    def run(self, arg=0):
        f = DoElf()
        if f.Show():
            output_file = f.txtFile.value
            if os.path.exists(output_file):
                s = "Output file already exists\n" \
                    "The output file already exists. " \
                    "Do you want to overwrite it?"
                if bool(AskUsingForm(s, "1")):
                    os.remove(output_file)
                else:
                    log('Elf not saved')
                    return
            write_symbols(output_file,
                          get_ida_is32(), get_ida_islsb(),
                          get_ida_ep(), get_ida_segments(), get_ida_symbols())
            f.Free()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DoElf_t()
